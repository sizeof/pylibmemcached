def run(max):
    cdef int i, x
    x = 1
    for i from 0 <= i < max:
        x = x + i
    return x
