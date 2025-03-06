import json
import os
from add_book import add_book
from view_books import view_books
from delete_book import remove_book
from search_book import search_books

BOOKS_FILE = 'books.json'

def load_books():
    if os.path.exists(BOOKS_FILE):
        with open(BOOKS_FILE, 'r') as file:
            return json.load(file)
    return []

def save_books(books):
    with open(BOOKS_FILE, 'w') as file:
        json.dump(books, file, indent=4)

def main():
    books = load_books()

    while True:
        print("\nBook Store Management System")
        print("1. Add Book")
        print("2. View Books")
        print("3. Search Book")
        print("4. Remove Book")
        print("5. Exit")
        
        choice = input("Select an option (1-5): ")

        if choice == '1':
            books = add_book(books)
            save_books(books)
        elif choice == '2':
            view_books(books)
        elif choice == '3':
            search_books(books)
        elif choice == '4':
            books = remove_book(books)
            save_books(books)
        elif choice == '5':
            save_books(books)
            print("Exiting program. All data saved.")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
