<#
.SYNOPSIS
    Scanne les images référencées dans docker-compose.yml (Trivy) et exporte un rapport lisible
.DESCRIPTION
    - Extrait les images du docker-compose.yml
    - Scanne chaque image avec Trivy (local ou via conteneur Docker)
    - Récupère la liste des containers en cours et leurs ports mappés
    - Exporte deux CSV lisibles : vulnerabilities.csv et containers_ports.csv
    - Si ImportExcel est disponible, génère un scan-report.xlsx avec deux onglets
.NOTES
    Exécuter dans PowerShell (VSCode terminal). Si le policy bloque les scripts:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#>

# --- Configuration ---
$ComposeFile = ".\docker-compose.yml"
$OutputDir = ".\scan-results"
$SeverityLevels = "CRITICAL,HIGH,MEDIUM"
$TrivyCmd = "trivy"   # laisse tel quel : on testera sa disponibilité
$UseDockerTrivyFallback = $true  # si trivy absent, utilisera le conteneur aquasec/trivy

# --- Préparations ---
if (-not (Test-Path $ComposeFile)) {
    Write-Host "❌ Fichier docker-compose.yml introuvable dans le dossier courant." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# --- Extraire les images depuis docker-compose.yml ---
Write-Host "`n🔍 Extraction des images depuis $ComposeFile ..." -ForegroundColor Cyan
$images = Select-String -Path $ComposeFile -Pattern "image:" | ForEach-Object {
    ($_ -split "image:")[1].Trim()
} | Select-Object -Unique

if ($images.Count -eq 0) {
    Write-Host "❌ Aucune image trouvée dans docker-compose.yml" -ForegroundColor Red
    exit 1
}

$images | ForEach-Object { Write-Host " - $_" }

# --- Vérifier si Trivy est installé localement ---
$TrivyInstalled = Get-Command $TrivyCmd -ErrorAction SilentlyContinue
if ($TrivyInstalled) {
    Write-Host "`n✅ Trivy détecté localement. Utilisation de Trivy local." -ForegroundColor Green
} elseif ($UseDockerTrivyFallback) {
    Write-Host "`n⚠️ Trivy non trouvé localement. Le conteneur Docker 'aquasec/trivy' sera utilisé." -ForegroundColor Yellow
} else {
    Write-Host "`n❌ Trivy non installé et fallback désactivé. Installe Trivy ou active le fallback." -ForegroundColor Red
    exit 1
}

# --- Récupérer containers en cours et ports mappés ---
Write-Host "`n📦 Récupération des containers en cours..." -ForegroundColor Cyan
# Format: Name|Image|Ports
$dockerPs = docker ps --format "{{.Names}}|{{.Image}}|{{.Ports}}" 2>$null
$containers = @()
foreach ($line in $dockerPs) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $parts = $line -split "\|",3
    $containers += [PSCustomObject]@{
        ContainerName = $parts[0]
        Image         = $parts[1]
        Ports         = $parts[2]
    }
}

# Sauvegarde rapide des containers
$containers | Export-Csv -Path (Join-Path $OutputDir "containers_ports.csv") -NoTypeInformation -Encoding UTF8

# --- Fonction utilitaire pour lancer Trivy (local ou conteneur) et produire JSON ---
function Run-TrivyJson {
    param(
        [string]$Image,
        [string]$OutputFile
    )

    Write-Host "Scanning image: $Image" -ForegroundColor Cyan

    if ($TrivyInstalled) {
        # Utilisation du binaire trivy local
        & $TrivyCmd image --severity $SeverityLevels --format json -o $OutputFile $Image
        $ExitCode = $LASTEXITCODE
        if ($ExitCode -ne 0) { Write-Host "⚠️ Trivy a retourné code $ExitCode pour $Image" -ForegroundColor Yellow }
    } else {
        # Utilisation du conteneur aquasec/trivy ; on pipe la sortie pour la capturer
        # On ne monte pas de volume pour éviter problèmes de path Windows -> on capture stdout
        $dockerCmd = "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --severity $SeverityLevels --format json $Image"
        try {
            $jsonOut = Invoke-Expression $dockerCmd 2>$null
            if ($jsonOut) {
                $jsonOut | Out-File -FilePath $OutputFile -Encoding utf8
            } else {
                Write-Host "⚠️ Aucun résultat Trivy pour $Image (container fallback)." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "❌ Erreur lors de l'exécution du conteneur Trivy pour $Image : $_" -ForegroundColor Red
        }
    }
}

# --- Scan images et collecte des vulnérabilités ---
Write-Host "`n🔎 Scan des images et extraction des vulnérabilités..." -ForegroundColor Cyan
$vulnsList = @()   # contiendra PSObjects: Image, Package, InstalledVersion, FixedVersion, Severity, VulnerabilityID, Title, Target
foreach ($img in $images) {
    # Nom de fichier sécurisé
    $sanitized = ($img -replace '[\/:]', '_')
    $jsonFile = Join-Path $OutputDir ("trivy_$sanitized.json")

    # Lancer Trivy
    Run-TrivyJson -Image $img -OutputFile $jsonFile

    if (-not (Test-Path $jsonFile)) {
        Write-Host "⚠️ Fichier de résultat absent pour $img, on passe." -ForegroundColor Yellow
        continue
    }

    # Parse JSON
    try {
        $raw = Get-Content $jsonFile -Raw | ConvertFrom-Json
    } catch {
        Write-Host "⚠️ Impossible de parser JSON Trivy pour $img : $_" -ForegroundColor Yellow
        continue
    }

    # Trivy structure: Results[] -> each Result has Target and Vulnerabilities[]
    if ($null -eq $raw.Results) { continue }

    foreach ($res in $raw.Results) {
        $target = $res.Target
        if ($null -eq $res.Vulnerabilities) { continue }

        foreach ($v in $res.Vulnerabilities) {
            $vulnObj = [PSCustomObject]@{
                ScannedImage     = $img
                Target           = $target
                VulnerabilityID  = $v.VulnerabilityID
                PkgName          = $v.PkgName
                InstalledVersion = $v.InstalledVersion
                FixedVersion     = $v.FixedVersion
                Severity         = $v.Severity
                Title            = ($v.Title -replace "[\r\n]+"," ")  # une ligne
                PrimaryURL       = $v.PrimaryURL
            }
            $vulnsList += $vulnObj
        }
    }
}

# --- Export CSV lisible des vulnérabilités ---
$vulnCsv = Join-Path $OutputDir "vulnerabilities.csv"
if ($vulnsList.Count -gt 0) {
    $vulnsList | Select-Object ScannedImage, Target, VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, PrimaryURL, Title |
        Sort-Object @{Expression='ScannedImage';Ascending=$true}, @{Expression='Severity';Ascending=$false} |
        Export-Csv -Path $vulnCsv -NoTypeInformation -Encoding UTF8

    Write-Host "`n✅ vulnerabilities.csv créé :" $vulnCsv -ForegroundColor Green
} else {
    Write-Host "`nℹ️ Aucune vulnérabilité trouvée (CRITICAL/HIGH/MEDIUM) selon Trivy." -ForegroundColor Green
    # Create empty CSV with headers for consistency
    @() | Select-Object ScannedImage, Target, VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, PrimaryURL, Title |
        Export-Csv -Path $vulnCsv -NoTypeInformation -Encoding UTF8
}

# --- Enrichir le tableau containers_ports.csv pour lier containers <-> vulnérabilités (si image correspond) ---
# On va ajouter colonne HasVulns (true/false) and MostSevere (max severity string)
$containers_enriched = @()
foreach ($c in $containers) {
    $img = $c.Image
    $related = $vulnsList | Where-Object { $_.ScannedImage -eq $img }
    $hasVulns = if ($related.Count -gt 0) { $true } else { $false }
    # Determine most severe (CRITICAL > HIGH > MEDIUM > otherwise NONE)
    $sevOrder = @{ 'CRITICAL' = 3; 'HIGH' = 2; 'MEDIUM' = 1 }
    if ($hasVulns) {
        $most = $related | Sort-Object { $sevOrder[$_.Severity] } -Descending | Select-Object -First 1
        $mostSev = $most.Severity
        $vulnCount = $related.Count
    } else {
        $mostSev = "NONE"
        $vulnCount = 0
    }
    $containers_enriched += [PSCustomObject]@{
        ContainerName = $c.ContainerName
        Image         = $c.Image
        Ports         = $c.Ports
        HasVulns      = $hasVulns
        MostSevere    = $mostSev
        VulnerabilitiesCount = $vulnCount
    }
}

$containers_enriched | Export-Csv -Path (Join-Path $OutputDir "containers_ports_enriched.csv") -NoTypeInformation -Encoding UTF8
Write-Host "✅ containers_ports_enriched.csv créé." -ForegroundColor Green

# --- Optionnel : générer un Excel si ImportExcel est présent ---
$excelPath = Join-Path $OutputDir "scan-report.xlsx"
$imp = Get-Module -ListAvailable -Name ImportExcel
if ($imp) {
    Write-Host "`n📘 Module ImportExcel détecté. Génération d'un fichier Excel..." -ForegroundColor Cyan
    try {
        # Convertir en DataTables / arrays
        $vulnsForExcel = $vulnsList | Select-Object ScannedImage, Target, VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, PrimaryURL, Title
        $containersForExcel = $containers_enriched | Select-Object ContainerName, Image, Ports, HasVulns, MostSevere, VulnerabilitiesCount

        # Exporter plusieurs feuilles
        $vulnsForExcel | Export-Excel -Path $excelPath -WorksheetName "Vulnerabilities" -AutoSize -TableName "Vulnerabilities"
        $containersForExcel | Export-Excel -Path $excelPath -WorksheetName "Containers" -AutoSize -TableName "Containers" -Append

        Write-Host "✅ Excel généré : $excelPath" -ForegroundColor Green
    } catch {
        Write-Host "⚠️ Erreur lors de la génération Excel : $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "`nℹ️ Module ImportExcel non installé. Si tu veux un .xlsx exécute : Install-Module -Name ImportExcel -Scope CurrentUser" -ForegroundColor Yellow
}

# --- Petit résumé console lisible ---
Write-Host "`n=== Résumé rapide ===" -ForegroundColor Cyan
$totalVulns = $vulnsList.Count
$totalContainers = $containers_enriched.Count
$containersWithVulns = ($containers_enriched | Where-Object { $_.HasVulns -eq $true }).Count
Write-Host "Images scannées     : $($images.Count)"
Write-Host "Containers vus      : $totalContainers"
Write-Host "Containers vulnérables : $containersWithVulns"
Write-Host "Vulnérabilités (CRIT/HIGH/MED) : $totalVulns"
Write-Host "`nFichiers produits dans : $OutputDir" -ForegroundColor Green
Write-Host " - vulnerabilities.csv" -ForegroundColor Green
Write-Host " - containers_ports.csv" -ForegroundColor Green
Write-Host " - containers_ports_enriched.csv" -ForegroundColor Green
if ($imp) { Write-Host " - scan-report.xlsx" -ForegroundColor Green }

Write-Host "`n✅ Terminé." -ForegroundColor Cyan
