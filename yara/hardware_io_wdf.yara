import "pe"

rule hardware_io_wdf {
  meta:
    description = "Designed to catch WDF x64 kernel drivers importing a memory-mapped I/O API (MmMapIoSpace)"

  strings:
	$wdf_api_name = "WdfVersionBind"
    
  condition:
    filesize < 1MB and
    uint16(0) == 0x5a4d and pe.machine == pe.MACHINE_AMD64 and 
    (pe.imports("ntoskrnl.exe", "MmMapIoSpace") or pe.imports("ntoskrnl.exe", "MmMapIoSpaceEx")) and
    $wdf_api_name and // WDF
    //not $wdf_api_name and // WDM
    for all signature in pe.signatures:
    (
	  not signature.subject contains "WDKTestCert"
    )
}
