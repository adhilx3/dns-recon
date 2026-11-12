param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)
python -m dns_recon.cli @Arguments
