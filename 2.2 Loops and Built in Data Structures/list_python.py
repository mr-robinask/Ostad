a= [1,2,3,4,5]

a_new=[i**2 for i in a]
print(a_new)


a_new = [i**2 for i in a if i%3 != 0]
print(a_new)


b_new = ['even' if i%2 == 0 else 'odd' for i in a]
print(b_new)