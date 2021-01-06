import time


def profile(func):
    def inner(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        print(f"--- {time.time() - start_time} seconds ---")
        return result

    return inner
