import idautils
import logging
import idaapi
import idc
import os
import binascii
import hashlib
import capstone
import requests
import numpy as np
import json


class Config(idaapi.action_handler_t):
    PLUGIN_NAME = "SAFE"
    PLUGIN_COMMENT = "CREATE SAFE SIGNATURE FOR A FUNCTIONS"
    PLUGIN_HELP = ""
    PLUGIN_HOTKEY = "Shift-S"
    CONFIG_FILE_PATH = os.path.join(idc.GetIdaDirectory(), "cfg/SAFE.cfg")
    SERVING_URL = "http://35.233.53.43:8500/v1/models/safe:predict"
    PLUGIN_TEST = False
    ACTION_NAME = "SAFE:ConfigAction"

    @staticmethod
    def init():

        NO_HOTKEY = ""
        SETMENU_INS = 0
        NO_ARGS = tuple()

        idaapi.register_action(idaapi.action_desc_t(Config.ACTION_NAME, "{} Config".format(Config.PLUGIN_NAME), Config()))
        idaapi.attach_action_to_menu("Options/", Config.ACTION_NAME, idaapi.SETMENU_APP)
        Config.load()

    @staticmethod
    def destory():

        idaapi.unregister_action(Config.ACTION_NAME)

        try:
            Config.save()
        except IOError:
            logging.warning("Failed to write config file")

    @staticmethod
    def load():
        try:
            maxlvl = int(open(Config.CONFIG_FILE_PATH, "rb").read())
            Config.SERVING_URL = maxlvl
        except:
            pass

    @staticmethod
    def save():
        config_data = str(Config.SERVING_URL)
        open(Config.CONFIG_FILE_PATH, "wb").write(config_data)

    @staticmethod
    def safe_config():
        input = idc.AskStr(str(Config.SERVING_URL), "Please enter the url for the tensorflow serving instance:")
        print("New Serving URL: " + input)
        Config.SERVING_URL = input

    def activate(self, ctx):
        self.safe_config()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# ------------------------------------------------------------------------------

class InstructionsConverter:

    def __init__(self, json_i2id):
        f = open(json_i2id, 'r')
        self.i2id = json.load(f)
        f.close()

    def convert_to_ids(self, instructions_list):
        ret_array = []
        # For each instruction we add +1 to its ID because the first
        # element of the embedding matrix is zero
        for x in instructions_list:
            if x in self.i2id:
                ret_array.append(self.i2id[x] + 1)
            elif 'X_' in x:
                # print(str(x) + " is not a known x86 instruction")
                ret_array.append(self.i2id['X_UNK'] + 1)
            elif 'A_' in x:
                # print(str(x) + " is not a known arm instruction")
                ret_array.append(self.i2id['A_UNK'] + 1)
            else:
                # print("There is a problem " + str(x) + " does not appear to be an asm or arm instruction")
                ret_array.append(self.i2id['X_UNK'] + 1)
        return ret_array

# ------------------------------------------------------------------------------

class FunctionNormalizer:

    def __init__(self, max_instruction):
        self.max_instructions = max_instruction

    def normalize(self, f):
        f = np.asarray(f[0:self.max_instructions])
        length = f.shape[0]
        if f.shape[0] < self.max_instructions:
            f = np.pad(f, (0, self.max_instructions - f.shape[0]), mode='constant')
        return f, length

    def normalize_function_pairs(self, pairs):
        lengths = []
        new_pairs = []
        for x in pairs:
            f0, len0 = self.normalize(x[0])
            f1, len1 = self.normalize(x[1])
            lengths.append((len0, len1))
            new_pairs.append((f0, f1))
        return new_pairs, lengths

    def normalize_functions(self, functions):
        lengths = []
        new_functions = []
        for f in functions:
            f, length = self.normalize(f)
            lengths.append(length)
            new_functions.append(f.tolist())
        return new_functions, lengths

# ------------------------------------------------------------------------------


def disassemble_func(address):
    func_dis = {}
    symbolic_calls = {}
    inst_num = 0
    flags = idc.get_func_flags(address)
    last_addr = address
    asm = ''
    cnt = 0
    for addr in FuncItems(address):
        cnt += 1
        ins = idautils.DecodeInstruction(addr)
        # print('decoded')
        byte_instr = idc.get_bytes(addr, ins.size)
        asm = asm + str(binascii.hexlify(byte_instr))
        inst_num = inst_num + 1
        last_addr = addr
        if idc.print_insn_mnem(addr) in ["call"]:
            # print('Call:'+str(ins))
            call_address = idc.get_operand_value(addr, 0)
            # print(call_address)
            start_addr = idc.first_func_chunk(call_address)
            symbolic_calls[start_addr] = idc.get_func_name(call_address)

    func_dis['bytecode'] = asm
    func_dis['symbolic_calls'] = symbolic_calls
    func_dis['start_address'] = idc.first_func_chunk(address)
    func_dis['end_address'] = last_addr
    func_dis['segment_address'] = idc.get_segm_start(address)
    func_dis['segment_name'] = idc.SegName(address)
    func_dis['name'] = idc.get_func_name(address)
    func_dis['inst_numbers'] = inst_num
    # attenzione sta cosa ci da la roba riconosciuta con flirt.
    func_dis['library_flag'] = flags & idc.FUNC_LIB
    
    print("Function contains {} instructions".format(cnt))
    
    return func_dis


def constantIndependt_hash(function1):
    string = ""
    for ins1 in function1:
        capstone_ins1 = ins1
        string = string + "<" + str(capstone_ins1.mnemonic)
        for op in capstone_ins1.operands:
            if (op.type == 1):
                string = string + ";" + str(op.reg)
        string = string + ">"
    m = hashlib.sha256()
    m.update(string.encode('UTF-8'))
    return m.hexdigest()


def filter_memory_references(i, symbols, API):
    inst = "" + i.mnemonic
    for op in i.operands:
        if (op.type == 1):
            inst = inst + " " + i.reg_name(op.reg)
        elif (op.type == 2):
            imm = int(op.imm)
            symbol = 'liavetevistiliavetevistisullerivedelfiume...INANIINANI'
            if str(imm) in symbols:
                symbol = str(symbols[str(imm)])
            if inst == 'call' and symbol in API:
                inst = inst + " " + symbol
            elif (-int(5000) <= imm <= int(5000)):
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


def filter_asm_and_return_instruction_list(address, asm, symbols, arch, mode, API):
    binary = binascii.unhexlify(asm)
    md = capstone.Cs(arch, mode)
    md.detail = True
    insns = []
    cap_insns = []
    cnt = 0;
    for i in md.disasm(binary, address):
        cnt += 1
        insns.append(filter_memory_references(i, symbols, API))
        cap_insns.append(i)
    print("Found {} instructions".format(cnt))
    return (constantIndependt_hash(cap_insns), insns)


def list_functions_to_disassembled(functions, arch, mode):
    ret = []
    for f in functions:
        # print((f,x))
        address = f['start_address']
        symbols = f['symbolic_calls']
        bytecode = f['bytecode']
        symbols_clean = {}
        # TODO fix this unclen and unholly ugliness
        for key, value in symbols.items():
            symbols_clean[key] = value.replace('.', '')
        # print(symbols_clean)
        insns = filter_asm_and_return_instruction_list(address, bytecode, symbols_clean, arch, mode, [])
        ret.append(insns)
    return ret

# ------------------------------------------------------------------------------


class SAFE_Plugin(idaapi.plugin_t):
    flags = 0
    comment = Config.PLUGIN_COMMENT
    help = Config.PLUGIN_HELP
    wanted_name = Config.PLUGIN_NAME
    wanted_hotkey = Config.PLUGIN_HOTKEY

    def __init__(self, *args, **kwargs):
        super(SAFE_Plugin, self).__init__(*args, **kwargs)
        self._chooser = None

    def init(self):
        Config.init()
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        try:
            addr = idaapi.get_screen_ea()
            # print("Addr: " + str(addr))

            fcn_name = idc.GetFunctionName(addr)
            print("----------------------------------------------------------------------------------------------------------")
            print("SAFE Signature For Function: " + fcn_name)

            info = idaapi.get_inf_structure()
            
            if info.procName == 'metapc':
                arch = capstone.CS_ARCH_X86
            
            if info.is_64bit():
                mode = capstone.CS_MODE_64
            elif info.is_32bit():
                mode = capstone.CS_MODE_32
                
            

            start = idc.get_func_attr(addr, idc.FUNCATTR_START)
            # print("Start: " + str(start))

            obj = disassemble_func(start)
            function = list_functions_to_disassembled([obj], arch, mode)[0]

            prepappend = 'X_'
            inst = [prepappend + x for x in function[1]]

            converter = InstructionsConverter(os.path.join(idc.GetIdaDirectory(), "plugins", "word2id.json"))
            normalizer = FunctionNormalizer(150)
            converted = converter.convert_to_ids(inst)
            instructions, lenghts = normalizer.normalize_functions([converted])
            payload = {"signature_name": "safe", "inputs": {"instruction": instructions, "lenghts": lenghts}}
            print(payload)
            r = requests.post(Config.SERVING_URL, data=json.dumps(payload))
            embeddings = json.loads(r.text)
            if "outputs" in embeddings:
                print(json.dumps(embeddings["outputs"][0]))
            else:
                raise ValueError("Something bad happened when computing embeddings")
        except Exception as e:
            logging.warning("exception", exc_info=True)
        return

    def term(self):
        Config.destory()


# ------------------------------------------------------------------------------


def PLUGIN_ENTRY():
    return SAFE_Plugin()


# ------------------------------------------------------------------------------


if Config.PLUGIN_TEST:
    print "{} - test".format(Config.PLUGIN_NAME)
    p = SAFE_Plugin()
    p.init()
    p.run()
    p.term()
