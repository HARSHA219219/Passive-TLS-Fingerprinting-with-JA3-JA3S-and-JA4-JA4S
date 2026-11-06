<#
Professor demonstration for tlsfp (passive JA3/JA3S/JA4/JA4S fingerprinting).

Run from the repository root in PowerShell:
    .\demo\run_demo.ps1                       # all steps, pauses between them
    .\demo\run_demo.ps1 -Step live            # one step: setup|validate|offline|evaluate|stability|live|spoof|unknown|server|report|results
    .\demo\run_demo.ps1 -NoPause              # no "press Enter" pauses
    .\demo\run_demo.ps1 -Interface "Wi-Fi 3"  # capture interface (python -m tlsfp ifaces)

Offline steps use only files in the repository (no network needed).
Live steps generate HTTPS traffic to www.wikipedia.org and need Npcap.
#>
param(
    [string]$Step = "all",
    [string]$Interface = "Wi-Fi 3",
    [switch]$NoPause
)
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { $Py = "python" }
$Db = Join-Path $Root "demo\demo.db"
$env:PYTHONWARNINGS = "ignore"

function Title($t) { Write-Host ""; Write-Host ("=" * 78) -ForegroundColor Cyan; Write-Host " $t" -ForegroundColor Cyan; Write-Host ("=" * 78) -ForegroundColor Cyan }
function Say($t) { Write-Host $t -ForegroundColor Yellow }
function Run($cmd) { Write-Host "PS> $cmd" -ForegroundColor DarkGray; Invoke-Expression $cmd }
function Pause-Demo { if (-not $NoPause) { Read-Host "`n[Enter] to continue" | Out-Null } }
function Want($name) { return ($Step -eq "all" -or $Step -eq $name) }

# ---------------------------------------------------------------------------------------------
if (Want "setup") {
    Title "0. Setup: load the curated reference database"
    Say "Learned from captures/train_v2.pcap (9 real clients) + published, cited fingerprints (FoxIO, Salesforce)."
    Remove-Item $Db -ErrorAction SilentlyContinue
    Run "& '$Py' -m tlsfp --db '$Db' db import data/reference_db.json"
    Run "& '$Py' -m tlsfp --db '$Db' db list --kind ja4"
    Pause-Demo
}

if (Want "validate") {
    Title "1. Extractor validation (published references + independent implementation)"
    Say "Unit tests: published JA3/JA3S vectors, FoxIO expected JA4/JA4S for 10 FoxIO pcaps, identification logic."
    Run "& '$Py' -m pytest -q -p no:cacheprovider tests"
    Say "`nCross-check against Wireshark/tshark's own JA3/JA3S/JA4 on our held-out capture:"
    Run "& '$Py' -m tlsfp validate captures/test_v2.pcap"
    Pause-Demo
}

if (Want "offline") {
    Title "2. Passive analysis of a capture file (offline pcap)"
    Say "Every ClientHello -> JA3/JA4 -> verdict; every ServerHello -> JA3S/JA4S. Nothing is decrypted."
    Run "& '$Py' -m tlsfp --db '$Db' analyze captures/test_v2.pcap --sni www.wikipedia.org --show-server | Select-Object -First 40"
    Pause-Demo
}

if (Want "evaluate") {
    Title "3. Identification accuracy on the held-out capture (ground truth = manifest)"
    foreach ($mode in @("", "--ja3-only", "--ja4-only")) {
        Say "`n--- evaluate $mode"
        Run "& '$Py' -m tlsfp --db '$Db' evaluate captures/test_v2.pcap --manifest captures/test_v2_manifest.json $mode"
    }
    Pause-Demo
}

if (Want "stability") {
    Title "4. Fingerprint randomisation: JA3 vs JA4 across repeated connections"
    Say "Chrome/Edge shuffle TLS extension order on every connection -> new JA3 each time; JA4 sorts -> stable."
    Run "& '$Py' -m tlsfp stability captures/test_v2.pcap --manifest captures/test_v2_manifest.json"
    Pause-Demo
}

if (Want "live") {
    Title "5. LIVE passive capture: curl vs browsers vs custom clients on the wire"
    Say "A second window sniffs '$Interface' (port 443). This window then drives real clients."
    $out = Join-Path $Root "demo\live_demo.pcap"
    $cap = "& '$Py' -m tlsfp --db '$Db' live -i '$Interface' -f 'tcp port 443' --sni wikipedia --resolve-process --show-server -w '$out' -t 120"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$Root'; $cap"
    Start-Sleep -Seconds 5
    Run "& '$Py' scripts/gen_traffic.py --clients curl,python-requests,python-custom,handcrafted,chrome,firefox --repeat 1 --gap 3 -o demo/live_manifest.json"
    Say "`nCompare 'proc=' (OS ground truth via psutil) with '=>' (fingerprint verdict) in the capture window."
    Pause-Demo
}

if (Want "unknown") {
    Title "6. Unknown client: a TLS stack that is not in the database"
    Say "Python 3.14 links OpenSSL 3.5 (the DB only knows Python 3.13 / OpenSSL 3.0) -> must be UNKNOWN, not guessed."
    Run "& '$Py' -m tlsfp --db '$Db' evaluate captures/test_v2.pcap --manifest captures/test_v2_manifest.json | Select-String 'not in DB|accuracy'"
    Pause-Demo
}

if (Want "spoof") {
    Title "7. Evasion: a hand-written client impersonating Chrome"
    $ja3 = & $Py -c "import json;print(next(r['raw'] for r in json.load(open('data/reference_db.json')) if r['label']=='Google Chrome' and r['kind']=='ja3'))"
    $ja4r = & $Py -c "import json;print(next(r['raw'] for r in json.load(open('data/reference_db.json')) if r['label']=='Google Chrome' and r['kind']=='ja4'))"
    Say "Replaying Chrome's JA4_r with scripts/custom_tls_client.py (Python, no browser involved):"
    Run "& '$Py' scripts/custom_tls_client.py www.wikipedia.org --ja4r '$ja4r'"
    Say "`nWhat the database says about that JA4 (it believes this is Chrome):"
    $sent = & $Py -c "import sys;sys.path.insert(0,'.');from tlsfp.builder import *;from tlsfp.fingerprints import *;from tlsfp.tls_parser import *;r=build_client_hello(spec_from_ja4_r(sys.argv[1],'www.wikipedia.org'));f=client_fingerprint(parse_client_hello(r[9:]));print(f.ja4, f.ja3)" $ja4r
    $j4, $j3 = $sent -split " "
    Run "& '$Py' -c `"import sys;sys.path.insert(0,'.');from tlsfp.db import FingerprintDB;m=FingerprintDB(r'$Db').identify('$j4','$j3');print('verdict:',m.label,'| status:',m.status)`""
    Say "`nHeld-out result over 10 spoofed connections:"
    Run "Import-Csv results/spoofing_results.csv | Format-Table ground_truth, combined_status, 'JA4+JA3 verdict' -AutoSize"
    Pause-Demo
}

if (Want "server") {
    Title "8. Server side: JA3S / JA4S"
    Say "Same server, different client -> different JA3S/JA4S. Published 'Sliver C2' JA4S also matches Wikipedia: false positive."
    Run "Import-Csv results/server_fingerprint_results.csv | Format-Table server_sni, ja4s, server_hellos, db_verdict, client_labels -AutoSize -Wrap"
    Pause-Demo
}

if (Want "report") {
    Title "9. Security monitoring view: history, unknowns, conflicts, malware-list hits"
    Run "& '$Py' -m tlsfp --db '$Db' analyze captures/test_v2.pcap --record | Out-Null"
    Run "& '$Py' -m tlsfp --db '$Db' report"
    Pause-Demo
}

if (Want "results") {
    Title "10. Saved experimental results"
    Run "Get-Content results/SUMMARY.md -TotalCount 40"
    Run "Get-ChildItem results | Format-Table Name, Length -AutoSize"
    Say "Charts: results/chart_*.png   (regenerate everything: python experiments/run_experiments.py)"
}
