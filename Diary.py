import os
import sys
from datetime import datetime

DIARY_DIR = "diaries"
os.makedirs(DIARY_DIR, exist_ok=True)

def get_path(filename_diary):
    return os.path.join(DIARY_DIR, filename_diary + ".txt")

def filename():
    filename_diary = input("What would you like to name your diary? ")
    path = get_path(filename_diary)
    if os.path.exists(path):
        print("❌ The diary name already exists. Please choose a different name.")
        filename_diary = input("Enter a new diary name: ")
        path = get_path(filename_diary)
    return path

def diary_writing():
    file = filename()
    try:
        print("\n📝 Start writing your diary below. Press Enter when done:\n")
        diary = input("> ")
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        with open(file, "w") as f:
            f.write(f"{timestamp}\n{diary}\n\n")
        print(f"\n✅ Diary saved as '{file}' with timestamp.")
    except KeyboardInterrupt:
        sys.exit("\nExiting.")

def existing_diary():
    filename_diary = input("Enter the name of the existing diary: ")
    file = get_path(filename_diary)
    try:
        if os.path.exists(file):
            print(f"\n📖 Writing to '{file}'. Type your new entry below:\n")
            diary = input("> ")
            timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            with open(file, "a") as f:
                f.write(f"\n{timestamp}\n{diary}\n\n")
            print(f"\n✅ Added new entry to '{filename_diary}.txt' with timestamp.")
        else:
            print("❌ That diary does not exist. Try again.")
    except KeyboardInterrupt:
        sys.exit("\nExiting.")

def view_diary():
    files = [f for f in os.listdir(DIARY_DIR) if f.endswith(".txt")]
    if not files:
        print("📂 No diaries found.")
        return
    print("\n📚 Your diaries:")
    for i, f in enumerate(files, 1):
        print(f" {i}. {f}")
    choice = input("\nEnter the number of the diary to view: ")
    try:
        selected = files[int(choice) - 1]
        path = os.path.join(DIARY_DIR, selected)
        with open(path, "r") as f:
            print("\n📖 Diary content:\n")
            print(f.read())
    except (IndexError, ValueError):
        print("❌ Invalid selection.")

def delete_diary():
    filename_diary = input("\nEnter the name of the diary to delete: ")
    file = get_path(filename_diary)
    if os.path.exists(file):
        confirm = input(f"⚠️ Are you sure you want to delete '{filename_diary}.txt'? (y/n): ").lower()
        if confirm == 'y':
            os.remove(file)
            print(f"🗑️ '{filename_diary}.txt' has been deleted.")
        else:
            print("❎ Deletion cancelled.")
    else:
        print("📂 No such diary found.")

def main():
    while True:
        print("\n***** Welcome to your Diary! *****\n")
        print("1. Create a new diary file")
        print("2. Write in an existing diary file")
        print("3. View all your diaries")
        print("4. Delete a diary file")
        print("5. Exit")
        try:
            choice = int(input("\nEnter your choice: "))
            if choice == 1:
                diary_writing()
            elif choice == 2:
                existing_diary()
            elif choice == 3:
                view_diary()
            elif choice == 4:
                delete_diary()
            elif choice == 5:
                sys.exit("👋 Thank you. See you soon!")
            else:
                print("❌ Invalid option. Try again.")
        except ValueError:
            print("❌ Please enter a number.")
        except KeyboardInterrupt:
            sys.exit("\n👋 Exiting. Goodbye!")

if __name__ == '__main__':
    main()
