# SAFE TEAM
#
#
# distributed under license: CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) #
#
import json
import r2pipe
import capstone
import binascii


class RadareFunctionAnalyzer:

    def __init__(self, filename, use_symbol, depth):
        self.r2 = r2pipe.open(filename, flags=['-2'])
        self.filename = filename
        self.arch, self.bits = self.get_arch()
        self.top_depth = 0
        self.use_symbol = use_symbol

    def __enter__(self):
        return self

    @staticmethod
    def filter_reg(op):
        return op["value"]

    @staticmethod
    def filter_imm(op):
        imm = int(op["value"])
        if -int(5000) <= imm <= int(5000):
            ret = str(hex(op["value"]))
        else:
            ret = str('HIMM')
        return ret

    @staticmethod
    def filter_mem(op):
        if "base" not in op:
            op["base"] = 0

        if op["base"] == 0:
            r = "[" + "MEM" + "]"
        else:
            reg_base = str(op["base"])
            disp = str(op["disp"])
            scale = str(op["scale"])
            r = '[' + reg_base + "*" + scale + "+" + disp + ']'
        return r

    @staticmethod
    def filter_memory_references_r(i):
        inst = "" + i["mnemonic"]

        for op in i["operands"]:
            if op["type"] == 'reg':
                inst += " " + RadareFunctionAnalyzer.filter_reg(op)
            elif op["type"] == 'imm':
                inst += " " + RadareFunctionAnalyzer.filter_imm(op)
            elif op["type"] == 'mem':
                inst += " " + RadareFunctionAnalyzer.filter_mem(op)
            if len(i["operands"]) > 1:
                inst = inst + ","

        if "," in inst:
            inst = inst[:-1]
        inst = inst.replace(" ", "_")

        return str(inst)
    
    @staticmethod
    def filter_memory_references(i):
        inst = "" + i.mnemonic
        for op in i.operands:
            if (op.type == 1):
                inst = inst + " " + i.reg_name(op.reg)
            elif (op.type == 2):
                imm = int(op.imm)
                if (-int(5000) <= imm <= int(5000)):
                    inst = inst + " " + str(hex(op.imm))
                else:
                    inst = inst + " " + str('HIMM')
            elif (op.type == 3):
                mem = op.mem
                if (mem.base == 0):
                    r = "[" + "MEM" + "]"
                else:
                    r = '[' + str(i.reg_name(mem.base)) + "*" + str(mem.scale) + "+" + str(mem.disp) + ']'
                inst = inst + " " + r
            if (len(i.operands) > 1):
                inst = inst + ","
        if "," in inst:
            inst = inst[:-1]
        inst = inst.replace(" ", "_")
        return str(inst)

    @staticmethod
    def get_callref(my_function, depth):
        calls = {}
        if 'callrefs' in my_function and depth > 0:
            for cc in my_function['callrefs']:
                if cc["type"] == "C":
                    calls[cc['at']] = cc['addr']
        return calls

    def get_instruction(self):
        instruction = json.loads(self.r2.cmd("aoj 1"))
        if len(instruction) > 0:
            instruction = instruction[0]
        else:
            return None

        operands = []
        if 'opex' not in instruction:
            return None

        for op in instruction['opex']['operands']:
            operands.append(op)
        instruction['operands'] = operands
        return instruction
        
    def get_instructions_capstone(self, asm):
        print("hello")
        

    def function_to_inst(self, my_function, depth):
        # print("INSR")
        asm = ""
        address = 0

        if self.use_symbol:
            s = my_function['vaddr']
        else:
            s = my_function['offset']
        self.r2.cmd('s ' + str(s))

        if self.use_symbol:
            end_address = s + my_function["size"]
            asm = self.r2.cmd("p8 {}".format(my_function["size"]))
        else:
            end_address = s + my_function["realsz"]
            asm = self.r2.cmd("p8 {}".format(my_function["realsz"]))
        
        # print("ADDR:" + str(my_function['offset']))
        binary = binascii.unhexlify(asm)

        #if self.arch == 'x86':
        #    cs_arch = capstone.CS_ARCH_X86
        cs_arch = capstone.CS_ARCH_X86

        if self.bits == 32:
            cs_bits = capstone.CS_MODE_32
        elif self.bits == 64:
            cs_bits = capstone.CS_MODE_64
        else:
            cs_bits = capstone.CS_MODE_64


        md = capstone.Cs(cs_arch, cs_bits)
        md.detail = True
        instructions = []
        cap_insns = []

        for i in md.disasm(binary, s):
            # print("i: " + str(i))
            instructions.append(self.filter_memory_references(i))

        return instructions, asm

    def get_arch(self):
        try:
            info = json.loads(self.r2.cmd('ij'))
            if 'bin' in info:
                arch = info['bin']['arch']
                bits = info['bin']['bits']
            else:
                arch = None
                bits = None
        except:
            print("Error loading file")
            arch = None
            bits = None
        return arch, bits

    def find_functions(self):
        self.r2.cmd('aac')
        self.r2.cmd('aap')
        try:
            function_list = json.loads(self.r2.cmd('aflj'))
            if len(function_list) < 10:
                self.r2.cmd('aaa')
                function_list = json.loads(self.r2.cmd('aflj'))
        except:
            function_list = []
        return function_list

    def find_functions_by_symbols(self):
        self.r2.cmd('aa')
        try:
            symbols = json.loads(self.r2.cmd('isj'))
            fcn_symb = [s for s in symbols if s['type'] == 'FUNC']
        except:
            fcn_symb = []
        return fcn_symb

    def analyze(self):
        result = {}
        if self.arch == None:
            return result
        if self.use_symbol:
            function_list = self.find_functions_by_symbols()
            function_list = [f for f in function_list if f['size'] > 50]
        else:
            function_list = self.find_functions()
            function_list = [f for f in function_list if f['realsz'] > 50]

        for my_function in function_list:
            if self.use_symbol:
                address = my_function['vaddr']
            else:
                address = my_function['offset']

            try:
                instructions, asm = self.function_to_inst(my_function, self.top_depth)
                prepappend = 'X_'
                instructions = [prepappend + x for x in instructions]
                result[my_function['name']] = {'filtered_instructions': instructions, "asm": asm, "address": address}
            except:
                #print("Error in functions: {} from {}".format(my_function['name'], self.filename))
                pass
        return result

    def close(self):
        self.r2.quit()

    def __exit__(self, exc_type, exc_value, traceback):
        self.r2.quit()



