class Book:
    def __init__(self, title, author, isbn):
        self.title = title
        self.author = author
        self.isbn = isbn

    def __str__(self):
        return f"{self.title} by {self.author} (ISBN: {self.isbn})"


class BookManager:
    def __init__(self):
        self.books = []

    def add_book(self, book):
        self.books.append(book)
        print(f'Added: {book}')

    def remove_book(self, isbn):
        for book in self.books:
            if book.isbn == isbn:
                self.books.remove(book)
                print(f'Removed: {book}')
                return
        print("Book not found.")

    def update_book(self, isbn, title=None, author=None):
        for book in self.books:
            if book.isbn == isbn:
                if title:
                    book.title = title
                if author:
                    book.author = author
                print(f'Updated: {book}')
                return
        print("Book not found.")

    def view_books(self):
        if not self.books:
            print("No books available.")
            return
        for book in self.books:
            print(book)

def main():
    manager = BookManager()

    while True:
        print("\nBook Management System")
        print("1. Add Book")
        print("2. Remove Book")
        print("3. Update Book")
        print("4. View Books")
        print("5. Exit")

        choice = input("Choose an option: ")

        if choice == '1':
            title = input("Enter title: ")
            author = input("Enter author: ")
            isbn = input("Enter ISBN: ")
            book = Book(title, author, isbn)
            manager.add_book(book)

        elif choice == '2':
            isbn = input("Enter ISBN of the book to remove: ")
            manager.remove_book(isbn)

        elif choice == '3':
            isbn = input("Enter ISBN of the book to update: ")
            title = input("Enter new title (leave blank to keep current): ")
            author = input("Enter new author (leave blank to keep current): ")
            manager.update_book(isbn, title if title else None, author if author else None)

        elif choice == '4':
            manager.view_books()

        elif choice == '5':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
 