__author__    = "sizeof <sizeof@sent.com>"
__version__   = "0.1.0"
__copyright__ = "Copyright (C) 2009 sizeof"
__license__   = "Apache License 2.0"

from python cimport \
    PyString_AsStringAndSize, \
    PyString_AsString, \
    PyString_FromStringAndSize, \
    PySequence_Length, \
    PyString_FromString, \
    PyDict_SetItem, PyList_GetItem
    
cdef extern from "stdlib.h":
    ctypedef unsigned int size_t
    ctypedef unsigned int time_t
    void *malloc(size_t size)
    void free(void *ptr)

cdef extern from "stdint.h":
    ctypedef unsigned short int uint16_t
    ctypedef unsigned int uint32_t
    ctypedef unsigned long long int uint64_t

cdef extern from "libmemcached/memcached.h":
    ctypedef enum memcached_return: 
        MEMCACHED_SUCCESS
        MEMCACHED_FAILURE
        MEMCACHED_HOST_LOOKUP_FAILURE
        MEMCACHED_CONNECTION_FAILURE
        MEMCACHED_CONNECTION_BIND_FAILURE
        MEMCACHED_WRITE_FAILURE
        MEMCACHED_READ_FAILURE
        MEMCACHED_UNKNOWN_READ_FAILURE
        MEMCACHED_PROTOCOL_ERROR
        MEMCACHED_CLIENT_ERROR
        MEMCACHED_SERVER_ERROR
        MEMCACHED_CONNECTION_SOCKET_CREATE_FAILURE
        MEMCACHED_DATA_EXISTS
        MEMCACHED_DATA_DOES_NOT_EXIST
        MEMCACHED_NOTSTORED
        MEMCACHED_STORED
        MEMCACHED_NOTFOUND
        MEMCACHED_MEMORY_ALLOCATION_FAILURE
        MEMCACHED_PARTIAL_READ
        MEMCACHED_SOME_ERRORS
        MEMCACHED_NO_SERVERS
        MEMCACHED_END
        MEMCACHED_DELETED
        MEMCACHED_VALUE
        MEMCACHED_STAT
        MEMCACHED_ERRNO
        MEMCACHED_FAIL_UNIX_SOCKET
        MEMCACHED_NOT_SUPPORTED
        MEMCACHED_NO_KEY_PROVIDED
        MEMCACHED_FETCH_NOTFINISHED
        MEMCACHED_TIMEOUT
        MEMCACHED_BUFFERED
        MEMCACHED_BAD_KEY_PROVIDED
        MEMCACHED_MAXIMUM_RETURN

    ctypedef enum memcached_behavior:
        MEMCACHED_BEHAVIOR_NO_BLOCK
        MEMCACHED_BEHAVIOR_TCP_NODELAY
        MEMCACHED_BEHAVIOR_HASH
        MEMCACHED_BEHAVIOR_KETAMA
        MEMCACHED_BEHAVIOR_SOCKET_SEND_SIZE
        MEMCACHED_BEHAVIOR_SOCKET_RECV_SIZE
        MEMCACHED_BEHAVIOR_CACHE_LOOKUPS
        MEMCACHED_BEHAVIOR_SUPPORT_CAS
        MEMCACHED_BEHAVIOR_POLL_TIMEOUT
        MEMCACHED_BEHAVIOR_DISTRIBUTION
        MEMCACHED_BEHAVIOR_BUFFER_REQUESTS
        MEMCACHED_BEHAVIOR_USER_DATA
        MEMCACHED_BEHAVIOR_SORT_HOSTS
        MEMCACHED_BEHAVIOR_VERIFY_KEY
        MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT
        MEMCACHED_BEHAVIOR_RETRY_TIMEOUT
        MEMCACHED_BEHAVIOR_KETAMA_WEIGHTED
        MEMCACHED_BEHAVIOR_KETAMA_HASH
        MEMCACHED_BEHAVIOR_BINARY_PROTOCOL
        MEMCACHED_BEHAVIOR_SND_TIMEOUT
        MEMCACHED_BEHAVIOR_RCV_TIMEOUT
        MEMCACHED_BEHAVIOR_SERVER_FAILURE_LIMIT
        MEMCACHED_BEHAVIOR_IO_MSG_WATERMARK
        MEMCACHED_BEHAVIOR_IO_BYTES_WATERMARK
        MEMCACHED_BEHAVIOR_IO_KEY_PREFETCH
        MEMCACHED_BEHAVIOR_HASH_WITH_PREFIX_KEY
        MEMCACHED_BEHAVIOR_NOREPLY
        MEMCACHED_BEHAVIOR_USE_UDP
        MEMCACHED_BEHAVIOR_AUTO_EJECT_HOSTS

    ctypedef enum memcached_server_distribution:
        MEMCACHED_DISTRIBUTION_MODULA
        MEMCACHED_DISTRIBUTION_CONSISTENT
        MEMCACHED_DISTRIBUTION_CONSISTENT_KETAMA
        MEMCACHED_DISTRIBUTION_RANDOM
        
    ctypedef enum memcached_hash:
        MEMCACHED_HASH_DEFAULT= 0
        MEMCACHED_HASH_MD5
        MEMCACHED_HASH_CRC
        MEMCACHED_HASH_FNV1_64
        MEMCACHED_HASH_FNV1A_64
        MEMCACHED_HASH_FNV1_32
        MEMCACHED_HASH_FNV1A_32
        MEMCACHED_HASH_HSIEH
        MEMCACHED_HASH_MURMUR
        MEMCACHED_HASH_JENKINS

    cdef enum:
        MEMCACHED_MAX_KEY

    struct memcached_st:
        pass

    struct memcached_server_st:
        pass

    memcached_st *memcached_create(memcached_st *ptr)
    void memcached_free(memcached_st *ptr)
    char *memcached_get(memcached_st *ptr, char *key, size_t key_length,
            size_t *value_length,
            uint32_t *flags,
            memcached_return *error)
    memcached_server_st *memcached_servers_parse(char *server_strings)
    memcached_return memcached_server_push(memcached_st *ptr, memcached_server_st *list)
    memcached_return memcached_increment(memcached_st *ptr, 
            char *key, size_t key_length,
            uint32_t offset,
            uint64_t *value)
    memcached_return memcached_decrement(memcached_st *ptr, 
            char *key, size_t key_length,
            uint32_t offset,
            uint64_t *value)
    memcached_return memcached_delete(memcached_st *ptr, char *key, size_t key_length,
            time_t expiration)
    memcached_return memcached_mget(memcached_st *ptr, 
                                char **keys, size_t *key_length, 
                                unsigned int number_of_keys)
    char *memcached_fetch(memcached_st *ptr, char *key, size_t *key_length, 
                      size_t *value_length, uint32_t *flags, 
                      memcached_return *error)
    memcached_return memcached_behavior_set(memcached_st *ptr, memcached_behavior flag, uint64_t data)
    uint64_t memcached_behavior_get(memcached_st *ptr, memcached_behavior flag)
    # notice: the old behavior_set API (before libmemcached 0.17) quote: Incompatible change in memcached_behavior_set() api. We now use a uint64_t, instead of a pointer.
    # memcached_return memcached_behavior_set(memcached_st *ptr, memcached_behavior flag, void *data)
    void memcached_server_list_free(memcached_server_st *ptr)

    memcached_return memcached_set(memcached_st *ptr, char *key, size_t key_length, char *value, size_t value_length, time_t expiration, uint32_t flags)
    memcached_return memcached_add(memcached_st *ptr, char *key, size_t key_length, char *value, size_t value_length, time_t expiration, uint32_t flags)
    memcached_return memcached_replace(memcached_st *ptr, char *key, size_t key_length, char *value, size_t value_length, time_t expiration, uint32_t flags)
    memcached_return memcached_append(memcached_st *ptr, char *key, size_t key_length, char *value, size_t value_length, time_t expiration, uint32_t flags)
    memcached_return memcached_prepend(memcached_st *ptr, char *key, size_t key_length, char *value, size_t value_length, time_t expiration, uint32_t flags)
   
    void memcached_quit(memcached_st *ptr)

#-----------------------------------------

from cPickle import dumps, loads
from string import join 
from time import strftime

MC_INCR = (1 << 0)
MC_DECR = (1 << 1)

cdef public enum:
    AAA

BEHAVIORS = {
    "no_block" : MEMCACHED_BEHAVIOR_NO_BLOCK,
    "tcp_nodelay" : MEMCACHED_BEHAVIOR_TCP_NODELAY,
    "hash" : MEMCACHED_BEHAVIOR_HASH,
    "ketama" : MEMCACHED_BEHAVIOR_KETAMA,
    "socket_send_size" : MEMCACHED_BEHAVIOR_SOCKET_SEND_SIZE,
    "socket_recv_size" : MEMCACHED_BEHAVIOR_SOCKET_RECV_SIZE,
    "cache_lookups" : MEMCACHED_BEHAVIOR_CACHE_LOOKUPS,
    "support_cas" : MEMCACHED_BEHAVIOR_SUPPORT_CAS,
    "poll_timeout" : MEMCACHED_BEHAVIOR_POLL_TIMEOUT,
    "distribution" : MEMCACHED_BEHAVIOR_DISTRIBUTION,
    "buffer_requests" : MEMCACHED_BEHAVIOR_BUFFER_REQUESTS,
    "user_data" : MEMCACHED_BEHAVIOR_USER_DATA,
    "sort_hosts" : MEMCACHED_BEHAVIOR_SORT_HOSTS,
    "verify_key" : MEMCACHED_BEHAVIOR_VERIFY_KEY,
    "connect_timeout" : MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT,
    "retry_timeout" : MEMCACHED_BEHAVIOR_RETRY_TIMEOUT,
    "ketama_weighted" : MEMCACHED_BEHAVIOR_KETAMA_WEIGHTED,
    "ketama_hash" : MEMCACHED_BEHAVIOR_KETAMA_HASH,
    "binary_protocol" : MEMCACHED_BEHAVIOR_BINARY_PROTOCOL,
    "snd_timeout" : MEMCACHED_BEHAVIOR_SND_TIMEOUT,
    "rcv_timeout" : MEMCACHED_BEHAVIOR_RCV_TIMEOUT,
    "server_failure_limit" : MEMCACHED_BEHAVIOR_SERVER_FAILURE_LIMIT,
    "io_msg_watermark" : MEMCACHED_BEHAVIOR_IO_MSG_WATERMARK,
    "io_bytes_watermark" : MEMCACHED_BEHAVIOR_IO_BYTES_WATERMARK,
    "io_key_prefetch" : MEMCACHED_BEHAVIOR_IO_KEY_PREFETCH,
    "hash_with_prefix_key" : MEMCACHED_BEHAVIOR_HASH_WITH_PREFIX_KEY,
    "noreply" : MEMCACHED_BEHAVIOR_NOREPLY,
    "use_udp" : MEMCACHED_BEHAVIOR_USE_UDP,
    "auto_eject_hosts" : MEMCACHED_BEHAVIOR_AUTO_EJECT_HOSTS
}



HASHERS = {
    'default' : MEMCACHED_HASH_DEFAULT,
    'md5' : MEMCACHED_HASH_MD5,
    'crc' : MEMCACHED_HASH_CRC,
    'fnv1_64' : MEMCACHED_HASH_FNV1_64,
    'fnv1a_64' : MEMCACHED_HASH_FNV1A_64,
    'fnv1_32' : MEMCACHED_HASH_FNV1_32,
    'fnv1a_32' : MEMCACHED_HASH_FNV1A_32,
    'hsieh' : MEMCACHED_HASH_HSIEH,
    'murmur' : MEMCACHED_HASH_MURMUR,
    'jenkins' : MEMCACHED_HASH_JENKINS
}





class Error(Exception):
    pass

cdef int _FLAG_PICKLE, _FLAG_INTEGER, _FLAG_LONG
_FLAG_PICKLE = 1<<0
_FLAG_INTEGER = 1<<1
_FLAG_LONG = 1<<2

cdef int MC_CMD_SET, MC_CMD_ADD, MC_CMD_APPEND, MC_CMD_PREPEND, MC_CMD_REPLACE
MC_CMD_SET = 1<<0
MC_CMD_ADD = 1<<1
MC_CMD_APPEND = 1<<2
MC_CMD_PREPEND = 1<<3
MC_CMD_REPLACE = 1<<4

cdef object _prepare_value(object val, uint32_t *flags):
    cdef uint32_t f
    f = 0

    if isinstance(val, basestring):
        flags[0] = 0
        pass
    elif isinstance(val, int):
        f = f | _FLAG_INTEGER
        val = str(val)
    elif isinstance(val, long):
        f = f | _FLAG_LONG
        val = str(val)
    else:
        f = f | _FLAG_PICKLE
        val = dumps(val, -1)

    flags[0] = f
    return val

cdef object _restore(char *c_val, size_t size, uint32_t flags):
    cdef object val

    val = PyString_FromStringAndSize(c_val, size)

    if flags == 0:
        pass
    elif flags & _FLAG_INTEGER:
        val = int(val)
    elif flags & _FLAG_LONG:
        val = long(val)
    elif flags & _FLAG_PICKLE:
        val = loads(val)

    return val
    
cdef class Behaviors

cdef class Client:
    cdef memcached_st *mc
    cdef int debug
    cdef object log
    cdef int log_threshold
    cdef public Behaviors behaviors
    cdef object b
    
    def __new__(self, servers, int debug=0, log=None, int log_threshold=100000, behaviors_dict=None):
        """
        Create a new Client object with the given list of servers.
        """
        cdef memcached_return retval
        cdef memcached_server_st *server_mc
        cdef uint64_t set
        cdef memcached_server_distribution distribution
        cdef Behaviors behaviors
        cdef object updated_behaviors
        
        self.b = [
            "no_block",
            "tcp_nodelay",
            "hash",
            "ketama",
            "socket_send_size",
            "socket_recv_size",
            "cache_lookups",
            "support_cas",
            "poll_timeout",
            "distribution",
            "buffer_requests",
            "user_data",
            "sort_hosts",
            "verify_key",
            "connect_timeout",
            "retry_timeout",
            "ketama_weighted",
            "ketama_hash",
            "binary_protocol",
            "snd_timeout",
            "rcv_timeout",
            "server_failure_limit",
            "io_msg_watermark",
            "io_bytes_watermark",
            "io_key_prefetch",
            "hash_with_prefix_key",
            "noreply",
            "use_udp",
            "auto_eject_hosts"
        ]
        
        self.debug = debug
        self.log = log
        self.log_threshold = log_threshold

        self.mc = memcached_create(NULL)
        if not self.mc:
            raise MemoryError

        server_string = ','.join(servers)

        server_mc = memcached_servers_parse(server_string) 
        retval = memcached_server_push(self.mc, server_mc)
        memcached_server_list_free(server_mc)
        
        #updated_behaviors = dict([(k,v) for k,v in kwargs.items() if BEHAVIORS.has_key(k)])
        
        self.behaviors = Behaviors(self, update=behaviors_dict)

#        if self.log is not None:
#            self.log.write("cmemcached: set behavior of %d\n" % MEMCACHED_BEHAVIOR_BINARY_PROTOCOL)
#            self.log.flush()

        set = MEMCACHED_HASH_FNV1A_32
        memcached_behavior_set(self.mc, MEMCACHED_BEHAVIOR_HASH, set)
        distribution = MEMCACHED_DISTRIBUTION_CONSISTENT
        memcached_behavior_set(self.mc, MEMCACHED_BEHAVIOR_DISTRIBUTION, distribution)

    def add_server(self, servers):
        cdef memcached_return retval
        cdef memcached_server_st *server_mc

        server_string = ','.join(servers)
        server_mc = memcached_servers_parse(server_string) 
        retval = memcached_server_push(self.mc, server_mc)
        memcached_server_list_free(server_mc)

    def __dealloc__(self):
        memcached_free(self.mc)

    def get_behaviors(self):
        cdef uint64_t bval
        res = {}
        cdef int i
        cdef object r
        
        for i from 0 <= i < 29:
            bval = memcached_behavior_get(self.mc, <memcached_behavior>i)
            r= PyList_GetItem(self.b, i)
            PyDict_SetItem(res, r, <int>bval)
        
        return res
        
    def set_behavior(self, flag, value):
        if flag not in BEHAVIORS:
            raise KeyError('Behavior flag not found: "%s"' % flag)
        
        cdef memcached_return retval
        
        retval = memcached_behavior_set(self.mc, BEHAVIORS[flag], value)
        
        return (retval == 0)
    
    def _store_impl(self, int cmd, key, val, time_t time=0):
        cdef Py_ssize_t key_len, bytes
        cdef char *c_key, *c_val
        cdef uint32_t flags
        cdef memcached_return retval

        PyString_AsStringAndSize(key, &c_key, &key_len)

        if key_len >= MEMCACHED_MAX_KEY:
            return 0

        val = _prepare_value(val, &flags)
        PyString_AsStringAndSize(val, &c_val, &bytes)
        
        if cmd & MC_CMD_SET:
            retval = memcached_set(self.mc, c_key, key_len, c_val, bytes, time, flags)
        elif cmd & MC_CMD_APPEND:
            retval = memcached_append(self.mc, c_key, key_len, c_val, bytes, time, flags)
        elif cmd & MC_CMD_PREPEND:
            retval = memcached_prepend(self.mc, c_key, key_len, c_val, bytes, time, flags)
        elif cmd & MC_CMD_ADD:
            retval = memcached_add(self.mc, c_key, key_len, c_val, bytes, time, flags)
        elif cmd & MC_CMD_REPLACE:
            retval = memcached_replace(self.mc, c_key, key_len, c_val, bytes, time, flags)

        return (retval == 0)

    def add(self, *args):
        return self._store_impl(MC_CMD_ADD, *args)

    def set(self, *args):
        return self._store_impl(MC_CMD_SET, *args)

    def append(self, *args):
        return self._store_impl(MC_CMD_APPEND, *args)

    def prepend(self, *args):
        return self._store_impl(MC_CMD_PREPEND, *args)

    def replace(self, *args):
        return self._store_impl(MC_CMD_REPLACE, *args)

    def delete(self, key, time_t time=0):
        cdef Py_ssize_t key_len
        cdef char *c_key
        cdef memcached_return retval

        PyString_AsStringAndSize(key, &c_key, &key_len)
        # memcached do not support the key whose length is bigger than MEMCACHED_MAX_KEY
        if key_len >= MEMCACHED_MAX_KEY:
            return 0

        # memcached_delete return MEMCACHED_SUCCESS(0) on success
        retval = memcached_delete(self.mc, c_key, key_len, time)
        # return true if delete successed, otherwise false
        return (retval == 0)

    def get(self, key):
        cdef char *c_key
        cdef Py_ssize_t key_len
        cdef uint32_t flags
        cdef size_t bytes
        cdef memcached_return rc
        cdef char * c_val

        PyString_AsStringAndSize(key, &c_key, &key_len)

        if key_len > MEMCACHED_MAX_KEY:
            return None

        flags = 0
        c_val = memcached_get(self.mc, c_key, key_len, &bytes, &flags, &rc)

        if c_val:
            val = _restore(<char *>c_val, bytes, flags)
            free(c_val)
        else:
            val = None

        return val

    def __contains__(self, key):
        return self.get_raw(key) is not None

    def __getitem__(self, key):
        if isinstance(key, basestring):
            return self.get(key)
        elif isinstance(key, list):
            return self.get_multi(key)
        else:
            return None

    def get_raw(self, key):
        cdef char *c_key
        cdef Py_ssize_t key_len
        cdef uint32_t flags
        cdef size_t bytes
        cdef memcached_return rc
        cdef char * c_val

        PyString_AsStringAndSize(key, &c_key, &key_len)

        if key_len > MEMCACHED_MAX_KEY:
            return None

        flags = 0
        c_val = memcached_get(self.mc, c_key, key_len, &bytes, &flags, &rc)

        if c_val:
            val = _restore(<char *>c_val, bytes, 0)
            free(c_val)
        else:
            val = None

        return val

    def get_multi(self, keys):
        cdef char **ckeys
        cdef Py_ssize_t *ckey_lens

        cdef memcached_return rc
        cdef uint32_t flags

        cdef Py_ssize_t key_len, nkeys
        cdef int i, valid_nkeys, index
        cdef char return_key[MEMCACHED_MAX_KEY]
        cdef size_t return_key_length
        cdef char *return_value
        cdef size_t bytes

        nkeys = PySequence_Length(keys)
        ckeys = <char **>malloc(sizeof(char *) * nkeys)
        ckey_lens = <Py_ssize_t *>malloc(sizeof(Py_ssize_t) * nkeys)

        index = 0
        for i from 0 <= i < nkeys:
            PyString_AsStringAndSize(keys[i], &(ckeys[index]), &(ckey_lens[index]))
            if ckey_lens[index] > 0 and ckey_lens[index] < MEMCACHED_MAX_KEY:
                index = index + 1

        valid_nkeys = index

        rc = memcached_mget(self.mc, ckeys, <size_t *>ckey_lens, valid_nkeys)

        result = {}

        flags = 0
        return_value= memcached_fetch(self.mc, return_key, &return_key_length,
                &bytes, &flags, &rc)
        while return_value != NULL:
            val = _restore(<char *>return_value, bytes, flags)
            key = PyString_FromStringAndSize(return_key, return_key_length)
            result[key] = val
            free(return_value)
            flags = 0
            return_value= memcached_fetch(self.mc, return_key, &return_key_length,
                &bytes, &flags, &rc)

        free(ckeys)
        free(ckey_lens)
        return result

    def get_list(self, keys):
        cdef unsigned int i
        cdef Py_ssize_t nkeys = PySequence_Length(keys)
        l_result = []
        result = self.get_multi(keys)
        
        if result:
            for i from 0 <= i < nkeys:
                if keys[i] in result:
                    l_result.append(result[keys[i]])
                else:
                    l_result.append(None)

        return l_result

    def incr(self, key, int val=1):
        return self.incr_decr(MC_INCR, key, val)

    def decr(self, key, int val=1):
        return self.incr_decr(MC_DECR, key, val)

    def incr_decr(self, int dir, key, int val=1):
        cdef uint64_t new_value
        cdef memcached_return rc
        cdef char *c_key
        cdef Py_ssize_t key_len
        
        PyString_AsStringAndSize(key, &c_key, &key_len)
        
        if key_len > MEMCACHED_MAX_KEY:
            return 0

        if dir == MC_INCR:
            rc = memcached_increment(self.mc, c_key, key_len, val, &new_value)
        else:
            rc = memcached_decrement(self.mc, c_key, key_len, val, &new_value)
        
        if rc != MEMCACHED_SUCCESS:
            return None
        return new_value

cdef class Behaviors:
    cdef Client cli

    def __cinit__(Behaviors self, Client cli, object update=None):
        self.cli = cli
        if update:
            for k, v in update.items():
                self[k] = v
    
    def __setitem__(self, k, uint64_t v):
        cdef memcached_return rc
        if k in BEHAVIORS:
            rc = memcached_behavior_set(self.cli.mc, BEHAVIORS[k], v)

    def __getitem__(self, k):
        cdef uint64_t bval
        if k in BEHAVIORS:
            bval = memcached_behavior_get(self.cli.mc, BEHAVIORS[k])
            return bval
        return None
    
    def __call__(self):
        cdef uint64_t bval
        res = {}
        
        for name, flag in BEHAVIORS.items():
            bval = memcached_behavior_get(self.cli.mc, flag)
            res[name] = bval
            
        return res
