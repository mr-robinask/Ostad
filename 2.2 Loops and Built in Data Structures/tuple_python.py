#()
#immutable
#no edit,delete,add(so no comrehension)
#dulicate support
a = (10,4,3,4,1)
print(a, type(a))

a = list(a)
a[0] = 100
print(a, type(a))

a = tuple(a)
print(a, type(a))