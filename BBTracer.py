import frida
import argparse
import sys
import os
import signal


'''
// Module info
'''
class Module:
    def __init__(self, name, base, size, path):
        self.name = name
        self.base = base
        self.size = size
        self.path = path

class AllModules:
    def __init__(self):
        self.modules = {}

    def add_module(self, module_dict):
        name = module_dict['name']  # Extract name with extension
        base = int(module_dict['base'], 16)  # Convert hex base to integer
        size = module_dict['size']  # Assuming size is already an int
        module = Module(name, base, size, module_dict['path'])
        self.modules[name] = module
        # Sort the modules based on the base address
        self.modules = dict(sorted(self.modules.items(), key=lambda x: x[1].base))

    def __getattr__(self, name): 
        return self.modules.get(name)
    
    def __getitem__(self, name): 
        return self.modules.get(name)
        
    def find_module_by_address(self, address):
        # Binary search to find the module
        low = 0
        high = len(self.modules) - 1
        # print("high:", high)
        while low <= high:
            mid = (low + high) // 2
            module = list(self.modules.values())[mid]
            # print(module.name, hex(module.base), hex(address), hex(module.base + module.size));
            if module.base <= address <= module.base + module.size:
                # print("return:", module.name)
                return module   # returns the module object, not the name!
            elif address < module.base:
                high = mid - 1
            else:
                low = mid + 1
        return None  # Address not found in any module


'''
// Parse the received data
'''
def parse_modules(module_obj):
    global all_modules_obj
    all_modules_obj.add_module(module_obj)

def parse_bb_events(events):
    global all_modules_obj
    global all_events_list
    
    for event in events:
        bbModule = all_modules_obj.find_module_by_address(int(event[0],0)); #bbModule is a Module object.    
        if bbModule is None:
            event_str = f"[None] {event[0]} , {event[1]} [None]\n"
        else:
            # event_str = f"[{bbModule.name}] {event[0]} , {event[1]} [{bbModule.name}]\n"  # Absolute addresses
            event_str = f"[{bbModule.name}] {hex(int(event[0],0) - bbModule.base)} , {hex(int(event[1],0) - bbModule.base)} [{bbModule.name}]\n"  # Relative addresses
            
        all_events_list.append(event_str)    
 

'''
// Receive the info from frida javascript client side.
'''
# receive the data
def on_message(message, data): 
    # global grecvd
    if message['type'] == 'send':
        # print("[*] Message from script:", message['payload'])
        process_recvd_data(message['payload']['recvd_cmd'], message['payload']['result'])
        # print(message)
        
    else:
        print(message)

# deal with the received data
def process_recvd_data(command, result):
    if command == 'modules':
        parse_modules(result)

    if command == 'bb_events':
        parse_bb_events(result)


'''
// Save the processed data to file
'''
def write_header(filename):
    global all_modules_obj
    
    with open(filename, 'w') as file:
        header_section_start = "* ======================== HEADER START ========================= *\n"
        file.write(header_section_start)
        
        header = "* {:<20}\t{:<12}\t{:<12}\t{}\n".format("Module_Name", "Module_Base", "Module_Size", "Module_Path")
        file.write(header)
        design_line = "* -----------------------------------------------------------------\n"
        file.write(design_line)
        
        for module in all_modules_obj.modules.values():
            line = "* {:<20}\t{:<12}\t{:<12}\t{}\n".format(module.name, hex(module.base), hex(module.size), module.path)
            file.write(line)
        
        header_section_end = "* ========================= HEADER END ========================== *\n"
        file.write(header_section_end)     

def write_bb_events(filename):
    global all_events_list
    with open(filename, 'a') as f:
        f.writelines(all_events_list)

def save_trace(filename):
    write_header(filename)    
    print("[+] Successfully written Header ((containing module info)")
    write_bb_events(filename)
    print("[+] Sucessfully written Trace")


'''
// Terminate the process after saving the data.
'''
def kill_process(pid):
    try:
        os.kill(pid, signal.SIGTERM)  # Force kill the process
        print(f"Process with PID {pid} terminated successfully.")
    except OSError as e:
        print(f"Failed to terminate process with PID {pid}: {e}")


'''
//  Global variables
'''
all_modules_obj = AllModules()  # To hold details about all the loaded modules in the process.
all_events_list = []    # To hold all the processed basic block events.



'''
// Frida Javascript side
'''

js_code = '''
var allModuleNames = []; // track all the loaded modules

const update_module_list = () => {
	
	const currModules = Process.enumerateModules();
	
	// Get the names of current modules from currModules
	var currModuleNames = [];
	for (var count=0; count<currModules.length; count++)
	{
		currModuleNames.push(currModules[count].name);
	}
	
	currModuleNames.forEach(currModuleName => {
		if (!allModuleNames.includes(currModuleName)) { 
			allModuleNames.push(currModuleName); // If a new module is found, add it to the allModuleNames
		
			send({"recvd_cmd": "modules", result: Process.findModuleByName(currModuleName)});
			
		}
	});
};

const mainThread = Process.enumerateThreads()[0];

Stalker.follow(mainThread.id, {
	events: {
		call: false,
		ret: false,
		exec: false,
		block: false,
		compile: true
	},

	onReceive: function(events) {
		var allEvents = Stalker.parse(events, {
			annotate: false,
			stringify: true
		});

		// Update module list or any other necessary actions
		update_module_list();

		// Send the basic block events to python side
		send({ "recvd_cmd": "bb_events", result: allEvents });
	}	
});


'''

def main():
    try:
        output_file_name = '[out]bb_trace.log'
        
        # parse the command line parameters
        parser = argparse.ArgumentParser(description='Frida script to trace execution of an executable.')
        parser.add_argument('parameters', nargs='+')
        args = parser.parse_args()
        # print(args)

        # create the process in suspended mode
        device = frida.get_local_device()
        pid = device.spawn(args.parameters) # We are first creating a device and then using spawn. If we directly use frida.spawn(), then we cant see the errors in our javascript instrumentation script. It will just fail if there are errors without any error messages.
        print('pid: %d' % pid)

        # attach frida instrumentaion engine to the suspended process
        session = device.attach(pid)

        # inject the instrumentation code into the process.
        script = session.create_script(js_code)
        script.on('message', on_message)
        script.load()

        # start the execution of process
        device.resume(pid)

        print("Press 'CTRL+C' to stop execution and save the trace.")
        sys.stdin.read()
        session.detach()

    except KeyboardInterrupt:
        print(f"[*] Writing trace data to output file '{output_file_name}' .....")
        save_trace(output_file_name)
        print("[*] Ending the process ...")
        kill_process(pid)  # Force kill the process

if __name__ == '__main__':
    main()