import os
import shutil

def clean_temp():
    temp_path = os.environ['TEMP']
    print(f'Cleaning Temp directory: {temp_path}')
    try:
        for filename in os.listdir(temp_path):
            file_path = os.path.join(temp_path, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f'Deleted file: {file_path}')
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
                print(f'Deleted directory: {file_path}')
    except Exception as e:
        print(f'Error cleaning Temp: {e}')

def clean_recent():
    recent_path = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Recent')
    print(f'Cleaning Recent files directory: {recent_path}')
    try:
        for filename in os.listdir(recent_path):
            file_path = os.path.join(recent_path, filename)
            os.remove(file_path)
            print(f'Deleted recent file: {file_path}')
    except Exception as e:
        print(f'Error cleaning Recent files: {e}')

def clean_prefetch():
    prefetch_path = r'C:\Windows\Prefetch'
    print(f'Cleaning Prefetch directory: {prefetch_path}')
    try:
        for filename in os.listdir(prefetch_path):
            file_path = os.path.join(prefetch_path, filename)
            os.remove(file_path)
            print(f'Deleted prefetch file: {file_path}')
    except Exception as e:
        print(f'Error cleaning Prefetch files: {e}')

if __name__ == "__main__":
    clean_temp()
    clean_recent()
    clean_prefetch()
    print('Cleaning completed.')
