import os
import collections

from ..coverage_file import CoverageFile

class BBTData(CoverageFile):
    """
    A [module] offset_start , offset_end [module] log parser.
    """

    def __init__(self, filepath):
        super(BBTData, self).__init__(filepath)

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    def get_offsets(self, module_name):
        return self.modules.get(module_name, {}).keys()

    #--------------------------------------------------------------------------
    # Parsing Routines - Top Level
    #--------------------------------------------------------------------------

    def _parse(self):
        """
        Parse modoff coverage from the given log file.
        """
        modules = collections.defaultdict(lambda: collections.defaultdict(int))
        with open(self.filepath) as f:
            for line in f:
                trimmed = line.strip()

                # skip empty lines
                if not len(trimmed): continue

                # skip lines starting with "*" or comments
                if trimmed.startswith('*') or trimmed[0] in [';', '#']: continue

                # Split line into module name and range
                # print(trimmed)
                parts = trimmed.split()
                # print(parts)
                # module_name = parts[0].strip('[]')
                module_name = os.path.splitext(parts[0].strip('[]'))[0]  # Remove extension
                # print(module_name)
                start_offset = int(parts[1], 16)
                # print(start_offset)
                end_offset = int(parts[3], 16)
                # print(end_offset)


                # Iterate through the range and increment coverage for each address
                for address in range(start_offset, end_offset):
                    modules[module_name][address] += 1

        self.modules = modules
