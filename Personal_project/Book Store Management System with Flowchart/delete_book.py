def remove_book(books):
    isbn = input("Enter the ISBN or Book ID of the book to remove: ")
    for book in books:
        if book['ISBN'] == isbn:
            books.remove(book)
            print(f"Book '{book['Title']}' removed successfully!")
            return books
    print("Error: No book found with this ISBN.")
    return books
