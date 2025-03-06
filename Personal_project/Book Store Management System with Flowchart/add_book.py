def add_book(books):
    title = input("Enter book title: ")
    author = input("Enter author name: ")
    isbn = input("Enter ISBN or Book ID: ")

# Check for duplicate ISBN
    if any(book['ISBN'] == isbn for book in books):
        print("Error: A book with this ISBN already exists.")
        return books

    genre = input("Enter genre: ")
    while True:
        try:
            price = float(input("Enter price: "))
            if price < 0:
                raise ValueError("Price must be a positive number.")
            break
        except ValueError as e:
            print(e)

    while True:
        try:
            quantity = int(input("Enter quantity in stock: "))
            if quantity < 0:
                raise ValueError("Quantity must be a non-negative integer.")
            break
        except ValueError as e:
            print(e)

    new_book = {
        "Title": title,
        "Author": author,
        "ISBN": isbn,
        "Genre": genre,
        "Price": f"{price:.2f}",
        "Quantity": quantity
    }

    books.append(new_book)
    print(f"Book '{title}' added successfully!")
    return books
