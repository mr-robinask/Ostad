def search_books(books):
    search_term = input("Enter the title, author, or ISBN of the book to search: ").lower()
    results = [book for book in books if search_term in book['Title'].lower() or
               search_term in book['Author'].lower() or
               search_term in book['ISBN']]

    if not results:
        print("No books found matching your search criteria.")
    else:
        print("\nSearch Results:")
        for book in results:
            print(f"Title: {book['Title']}, Author: {book['Author']}, "
                  f"ISBN: {book['ISBN']}, Genre: {book['Genre']}, "
                  f"Price: {book['Price']}, Quantity: {book['Quantity']}")
