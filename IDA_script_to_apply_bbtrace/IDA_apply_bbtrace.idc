#include <idc.idc>

static apply_color(start_address, end_address, color)
{
    auto ea;
    // Iterate through the address range
    for (ea = start_address; ea < end_address; ea++)
    {
        // Set the color for each address
        set_color(ea, CIC_ITEM, color);
    }
}

static main()
{
	// Light green color in RGB format
	auto light_green_color = 0xccff99;
	
	
	auto modulename = get_root_filename(); // Get the currently loaded filename.
	auto modulename_lower = tolower(modulename);
	msg("Moduled loaded: %s\n", modulename);
	
	auto moduleBase = get_imagebase();
	// print(moduleBase);
	// msg("0x%X",moduleBase);

	// auto tracefile = "C:\\Users\\ElNino\\Desktop\\solo_tracers\\bb_tracer&call_tracer&transform\\[out]bb_trace.log";
	auto tracefile = ask_file(0, "*.log", "Choose the trace file");
	msg("Trace file loaded: %s\n\n", tracefile);
	
	auto fileHandle = fopen(tracefile, "r"); // Open the file for reading

    auto line;
	
	msg("Basic Blocks:\n");
	msg("-----------------\n");
	while ((line = readstr(fileHandle)) != -1) {
		auto fc = substr(line, 0, 1); // Get the first character of the line
		
		if (fc != "[") {
			continue;
		}
		
		// Find the start of the module name
		auto moduleNameStart = stristr(line, "[");
		if (moduleNameStart == -1) {
			continue; // Couldn't find module name
		}
		
		// Find the end of the module name
		auto moduleNameEnd = stristr(line, "]");
		if (moduleNameEnd == -1) {
			continue; // Couldn't find module name
		}
		
		// Extract the module name
		auto moduleName = substr(line, moduleNameStart + 1, moduleNameEnd);
		
		// Find the start of the start address
		auto startAddressStart = stristr(line, "0x");
		if (startAddressStart == -1) {
			continue; // Couldn't find start address
		}
		
		// Find the end of the start address
		auto startAddressEnd = stristr(line, ",");
		if (startAddressEnd == -1) {
			continue; // Couldn't find start address
		}
		
		// Extract the start address
		auto startAddress = substr(line, startAddressStart, startAddressEnd);
		
		// Find the start of the end address
		auto endAddressStart = startAddressEnd + 1; // The end address starts right after the comma
		if (endAddressStart == -1) {
			continue; // Couldn't find end address
		}
		
		// Find the end of the end address
		auto endAddressEnd = stristr(line, " [");
		if (endAddressEnd == -1) {
			continue; // Couldn't find end address
		}
		
		// Extract the end address
		auto endAddress = substr(line, endAddressStart, endAddressEnd);
		
		// Print extracted information
		// msg("Module Name: %s, Start Address: %s, End Address: %s\n", moduleName, startAddress, endAddress);
		// msg("Module Name: %s, Start Address: %s, End Address: \n", moduleName, startAddress);
		// msg("Module Name: %s, Start Address: %s, End Address: %s\n", moduleName, op_hex(startAddress,0), op_hex(endAddress,0));
		auto moduleName_lower = tolower(moduleName);
		if (modulename_lower == moduleName_lower)
		{
			// msg("Module Name: %s, Start Address: 0x%X, End Address: 0x%X\n", moduleName, moduleBase+startAddress, moduleBase+endAddress);
			msg("0x%X, 0x%X\n", moduleBase+startAddress, moduleBase+endAddress);
			// set_color(moduleBase+startAddress, CIC_ITEM, light_green_color);
			apply_color(moduleBase+startAddress, moduleBase+endAddress, light_green_color);
			
		}
		// msg(startAddress);
	}
	
	fclose(fileHandle); // Close the file
}

