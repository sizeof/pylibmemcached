cdef extern from "Python.h":
    ctypedef int Py_ssize_t
    int PyString_AsStringAndSize(object obj, char **s, Py_ssize_t *len) except -1
    object PyString_FromStringAndSize(char * v, Py_ssize_t len)
    char *PyString_AsString(object obj) except NULL
    int PySequence_Length(object o)
