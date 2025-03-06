def view_books(books):
    if not books:
        print("No books available.")
        return

    print("\nList of Books:")
    for book in books:
        print(f"Title: {book['Title']}, Author: {book['Author']}, "
              f"ISBN: {book['ISBN']}, Genre: {book['Genre']}, "
              f"Price: {book['Price']} Tk, Quantity: {book['Quantity']}")
