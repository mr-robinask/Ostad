# key: value pair
# {"Robin" : 29}
#key must be immutable(int,float,str,tuple)
#mutable,no indexing, unordered
#value can be accessed by key
#{}
#keys(),values(), k,v  , items(), get()


a = {"Robin" : 29,"Avro" : 28,"Meraz" : 27}
print(a["Avro"])

a["Avro"] = 23 #value changing
print(a["Avro"])

a["Rahat"] = 25 #will be added if not there
print(a)

#All keys list,All values ( keys() )
print(a.keys())
print(a.values(),"\n")

for i in a.keys():
    print(a[i])

print("\n")

#key value pair print( item() )
for k,v in a.items():
    print(k,v)
    
#get function(to check ,won't add)
print(a.get("Hamim","Data Not Found"))
print(a)


#Dictionary Comprehension
#1 - 5
#1: Odd
#2 : Even

print("\n")
a={i: "Even" if i%2 == 0 else "Odd" for i in range(10)}
print(a)

print("\n")
print(a.get(4))

