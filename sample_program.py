def add(a, b):
    return a + b


def test_add():
    assert add(30, 4) == 34
    assert add(2, 67) == 69


if __name__ == "__main__":
    test_add()
