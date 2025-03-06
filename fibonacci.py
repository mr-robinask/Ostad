def fibonacci_by_terms(n):
    """Generate Fibonacci series for a given number of terms."""
    if n <= 0:
        return []
    series = [0, 1]
    for _ in range(n - 2):
        series.append(series[-1] + series[-2])
    return series[:n]

def fibonacci_by_max_value(max_value):
    """Generate Fibonacci series up to a given maximum value."""
    if max_value < 0:
        return []
    series = [0, 1]
    while series[-1] + series[-2] <= max_value:
        series.append(series[-1] + series[-2])
    return series

def get_valid_input(prompt):
    """Get a valid non-negative integer input from the user."""
    while True:
        try:
            value = int(input(prompt))
            if value >= 0:
                return value
            else:
                print("Please enter a non-negative integer.")
        except ValueError:
            print("Invalid input! Please enter a valid integer.")

def main():
    while True:
        print("\nChoose an option:")
        print("1. Generate Fibonacci series by number of terms")
        print("2. Generate Fibonacci series by maximum value")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            num_terms = get_valid_input("Enter the number of terms: ")
            result = fibonacci_by_terms(num_terms)
            print(f"Fibonacci series ({num_terms} terms): {', '.join(map(str, result))}")

        elif choice == "2":
            max_value = get_valid_input("Enter the maximum value: ")
            result = fibonacci_by_max_value(max_value)
            print(f"Fibonacci series (up to {max_value}): {', '.join(map(str, result))}")

        elif choice == "3":
            print("Exiting program. Goodbye!")
            break

        else:
            print("Invalid choice! Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
