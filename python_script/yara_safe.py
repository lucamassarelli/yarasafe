import os
import hashlib
import json
from FunctionAnalyzerRadare import RadareFunctionAnalyzer
from InstructionsConverter import InstructionsConverter
from FunctionNormalizer import FunctionNormalizer
import requests
from multiprocessing import Process, Queue
import traceback
import tempfile
import sys


tf_serving = "http://35.233.53.43:8500/v1/models/safe:predict"

def read_string_from_pipe(f):
    byte = True
    received = ""
    while byte:
        byte = os.read(f,1)
        if byte == b'\0':
            break
        received += byte.decode("utf-8")
    return received

def read_stream_from_pipe(f, bytes_to_read):
    received = bytes()
    for i in range(0, bytes_to_read):
        byte = os.read(f,1)
        received += byte
    return received

def write_string_to_pipe(f, msg):
    for c in msg:
        os.write(f,bytes(c, 'utf-8'))
    os.write(f, b'\0')
    return len(msg)

def wait_for_programs(f):
    msg_bytes = int(read_string_from_pipe(f))
    msg = read_stream_from_pipe(f, msg_bytes)
    return msg, msg_bytes

def check_exit(msg):
    if len(msg) == 4 and msg == b"exit":
        return True
    else:
        return False

def worker(queue, name):
    #analyzer = IDAFunctionAnalyzer(name, False, 0)
    analyzer = RadareFunctionAnalyzer(name, False, 0)
    functions = analyzer.analyze()
    queue.put(functions)

def embedd_program(program, converter):
    try:
        tmp_file = tempfile.NamedTemporaryFile("wb", delete=False)
        tmp_file.write(program)
        name = tmp_file.name
        tmp_file.close()
        #print("[DEBUG] Analyzing file with sha256: {}, size: {}".format(hash, str(len(program))))

        q = Queue()
        p = Process(target=worker, args=(q, name))
        p.start()
        functions = q.get()
        p.join()

        normalizer = FunctionNormalizer(150)
        converted = []
        for f in functions:
            converted.append(converter.convert_to_ids(functions[f]['filtered_instructions']))
        instructions, lenghts = normalizer.normalize_functions(converted)
        payload = {"signature_name":"safe", "inputs":{"instruction":instructions, "lenghts":lenghts}}
        #print("[Python] Computing embedding, found {} function".format(len(converted)))

        r = requests.post(tf_serving, data=json.dumps(payload))
        embeddings = json.loads(r.text)

        result = {}
        if "outputs" not in embeddings:
            if os.path.exists(name):
                os.remove(name)
            return result

        for i, f in enumerate(functions):
            result[f] = embeddings["outputs"][i]

    except:
        traceback.print_exc()
        result = {}
        if os.path.exists(name):
            os.remove(name)

    try:
        os.remove(name)
    except:
        pass

    return(result)

def launch(bytes):
    #print("[Python] Hello from python len: {}".format(len(bytes)))
    w2id_path = os.path.join(os.environ["YARAPYSCRIPT"], "i2v", "word2id.json")
    converter = InstructionsConverter(w2id_path)
    result = embedd_program(bytes, converter)
    #print("[Python] embedding done")
    return json.dumps(result)

if __name__ == "__main__":
    f = open(sys.argv[1], "rb")
    content = f.read()
    f.close()
    w2id_path = os.path.join(os.environ["YARAPYSCRIPT"], "i2v", "word2id.json")
    converter = InstructionsConverter(w2id_path)
    result = embedd_program(content, converter)
    #print("[Python] embedding done")
    print(json.dumps(result))









