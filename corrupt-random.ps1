# ==========================================
# corrupt-random.ps1
# Corrompe 1 archivo .bin aleatorio
# ==========================================

$dir = "X:\cloudA"

$files = Get-ChildItem $dir -Filter *.bin

if ($files.Count -eq 0) {
    Write-Host "No se encontraron .bin en $dir"
    exit
}

$file = Get-Random $files

Write-Host "Corrompiendo archivo: $($file.FullName)"

$fs=[System.IO.File]::Open($file.FullName,'Open','ReadWrite')

$pos=Get-Random -Minimum 0 -Maximum $fs.Length
$value=Get-Random -Minimum 0 -Maximum 256

$fs.Seek($pos,0)
$fs.WriteByte($value)

$fs.Close()

Write-Host "Byte modificado en posicion $pos con valor $value"
Write-Host "Corrupcion aleatoria completada."