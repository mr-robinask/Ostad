#dulicate not suorted
#no indexing,unordered in memory
#{}
#add()

a={1,2,2,3,4}
#a[0]=100
print(a,type(a))

#intersection(only the common value)
b={10,20,20,3,40}
b.add(100)
print(a.intersection(b))

#union(all values excet dulicate)
print(a.union(b))