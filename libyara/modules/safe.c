/* SAFE TEAM
#
#
# distributed under license: CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) #
*/


#include <yara/modules.h>
#include <yara/mem.h>
#include <python/Python.h>
#include <jansson.h>
#include <pthread.h>

#define MODULE_NAME safe

// macros for handling errors
#define handle_error(msg)           do { perror(msg); exit(EXIT_FAILURE); } while (0)

pthread_t tid;


void initialize_python(bool threads) {
    Py_Initialize();

    if(threads) {
        PyEval_InitThreads();
        PyEval_ReleaseLock();
    }

    tid = pthread_self();

    char* pythonhome = NULL;
    pythonhome = getenv("YARAPYSCRIPT");
    if(!pythonhome) {
        handle_error("YARAPYSCRIPT ENV VAR IS NOT DEFINED");
    }

    PyObject* sysPath = PySys_GetObject((char*)"path");
    PyObject* programName = PyUnicode_FromString(pythonhome);
    PyList_Append(sysPath, programName);
}

double** parse_json(char* msg, int* num_func) {
    json_t* json = NULL;
    json_t *array = NULL;
    json_t *arr_value = NULL;
    json_error_t json_error;

    const char *key;
    size_t index;
    int count = 0;

    json = json_loadb(msg, strlen(msg), 0, &json_error);
    *(num_func) = json_object_size(json);
    size_t embedding_size = 100;

    double** emb_matrix = yr_calloc(*(num_func), sizeof(double*));
    if(emb_matrix == NULL) handle_error("Error allocating rows of embedding matrix");

    json_object_foreach(json, key, array) {
        emb_matrix[count] = yr_calloc(embedding_size, sizeof(double));
        if(emb_matrix[count] == NULL) handle_error("Error allocating columns of embedding matrix");
        json_array_foreach(array, index, arr_value) {
            emb_matrix[count][index] = json_real_value(arr_value);
        }
        count++;
    }

    yr_free((void*)key);
    json_decref(json);

    return(emb_matrix);
}

int launch_python_script(char *bytes, int size, double ***embedding_matrix) {

    // I Need to check if yara is running multi threaded or not.
    // If not i need to re-initialize the python interpreter without thread support
    pthread_t aa = pthread_self();
    if(aa == tid) {
        Py_Finalize();
        initialize_python(false);
    }

    PyGILState_STATE state = PyGILState_Ensure();

    PyObject *pName, *pModule, *pFunc;
    PyObject *pArgs, *pValue;


    pName = PyUnicode_FromString("yara_safe");
    pModule = PyImport_Import(pName);
    if (!pModule) {
        PyErr_Print();
        handle_error("Error importing module yara_safe");
    }

    pFunc = PyObject_GetAttrString(pModule, "launch");
    if (!pFunc) {
        PyErr_Print();
        handle_error("Error finding function lauch for module yara_safe");
    }

    pArgs = PyTuple_New(1);

    pValue = PyBytes_FromStringAndSize(bytes, size);
    PyTuple_SetItem(pArgs, 0, pValue);

    pValue = PyObject_CallObject(pFunc, pArgs);
    if (!pValue) {
        PyErr_Print();
        handle_error("Error calling function launch");
    }
    char* response = PyUnicode_AsUTF8(pValue);
    int num_func;
    *(embedding_matrix) = parse_json(response, &num_func);

    Py_DECREF(pModule);
    Py_DECREF(pArgs);
    Py_DECREF(pName);
    Py_DECREF(pValue);
    Py_DECREF(pFunc);

    PyGILState_Release(state);

    return(num_func);
}



double compute_dot_product(double* v1, double* v2, int size) {
    int i;
    double dot = 0.0, denom_a = 0.0, denom_b = 0.0 ;
    //printf("DOT %lf %lf \n", v1[0],v2[0]);
    for(i = 0; i < size; i++) {
        dot += v1[i] * v2[i];
        denom_a += v1[i] * v1[i] ;
        denom_b += v2[i] * v2[i] ;
    }
    return(dot / (sqrt(denom_a) * sqrt(denom_b)));
}

double* matrix_per_vector(double** matrix, double* vector, int row_size, int column_size, double* result) {
    int i;
    for(i=0; i < row_size; i++) {
        result[i] = compute_dot_product(*(matrix+i), vector, column_size);
        //printf("%lf ", result[i]);
    }
    //printf("\n");
    return(result);
}

double* parse_json_argument(char* msg) {
    json_t *json = NULL;
    json_t *arr_value = NULL;
    json_error_t json_error;

    json = json_loadb(msg, strlen(msg), 0, &json_error);
    if(!json) {
        printf("ERROR JSON: %s", json_error.text);
    }

    int index;

    double* target_emb = yr_malloc(100 * sizeof(double));
    if(target_emb == NULL) handle_error("Error allocating target embedding matrix");

    json_array_foreach(json, index, arr_value) {
        target_emb[index] = json_real_value(arr_value);
    }

    json_decref((json_t*) json);
    return(target_emb);
}

double maxValue(double* myArray, size_t size) {
    size_t i;
    double maxValue = myArray[0];
    for (i = 1; i < size; ++i) {
        //printf("%lf ", myArray[i]);
        if ( myArray[i] > maxValue ) {
            maxValue = myArray[i];
        }
    }
    return maxValue;
}

define_function(similarity) {


    char* str = string_argument(1);
    double* target_emb = parse_json_argument(str);

    YR_OBJECT* parent_obj = parent();

    double** embedding_matrix = parent_obj->data;



    int num_func = get_integer(parent_obj, "num_func");

    if(embedding_matrix == NULL && num_func == 0) {
        yr_free(target_emb);
        return_float(-1.0)
    }

    double* result = yr_calloc(num_func, sizeof(double));

    if(result == NULL) {
        handle_error("error allocating results in matrix per vector");
    }

    if(num_func >= 0) {
        matrix_per_vector(embedding_matrix, target_emb, num_func, 100, result);
    }

    double my_max = maxValue(result, num_func);
    //printf("SIM: %lf \n", my_max);

    yr_free(result);
    yr_free(target_emb);
    return_float(my_max);
}

begin_declarations;

    declare_integer("num_func");
    declare_float("tid");
    declare_function("similarity", "s", "f", similarity);

end_declarations;

int module_initialize(YR_MODULE* module) {

    initialize_python(true);

    return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module) {
    //Py_Finalize();
    return ERROR_SUCCESS;
}

int module_load(
        YR_SCAN_CONTEXT* context,
        YR_OBJECT* module_object,
        void* module_data,
        size_t module_data_size)
{
    YR_MEMORY_BLOCK* block = NULL;
    YR_MEMORY_BLOCK_ITERATOR* iterator = NULL;

    block = first_memory_block(context);
    iterator = context->iterator;

    int size = 0;
    char * buf = NULL;

    foreach_memory_block(iterator, block) {
        buf = yr_realloc(buf, block->size);
        const uint8_t* block_data = block->fetch_data(block);
        memcpy(buf, block_data + size, block->size);
        size += block->size;
    }

    double **embedding_matrix;
    int num_func;
    if(buf[0] == 77 && buf[1] == 90) { //Check if file is PE
        num_func = launch_python_script(buf, size, &embedding_matrix);
        set_integer(num_func, module_object, "num_func");
        module_object->data = embedding_matrix;
    } else {
            num_func = 0;
            set_integer(num_func, module_object, "num_func");
            module_object->data = NULL;
    }
    yr_free(buf);
    return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
    //printf("Done");
    fflush(0);
    yr_free(module_object->data);
    return ERROR_SUCCESS;
}


#undef MODULE_NAME
