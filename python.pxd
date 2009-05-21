cdef extern from "Python.h":
    int PyString_AsStringAndSize(object obj, char **s, Py_ssize_t *len) except -1
    object PyString_FromStringAndSize(char * v, Py_ssize_t len)
    object PyString_FromString(char *v)
    char *PyString_AsString(object obj) except NULL
    int PySequence_Length(object o)
    int PyDict_SetItem(object obj, object k, object v) except -1
    object PyList_GetItem(object list, int index)
