from functools import singledispatch, update_wrapper


def methdispatch(func):
    dispatcher = singledispatch(func)
    def wrapper(*args, **kwargs):
        return dispatcher.dispatch(args[1].__class__)(*args, **kwargs)
    wrapper.register = dispatcher.register
    update_wrapper(wrapper, func)
    return wrapper

class FieldElement:
    """models an element of a Finite Field"""
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = f"num: {num} not in field range 0 to {prime-1}"
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        return f"FieldElement_{self.prime}({self.num})"

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        return self.num != other.num or self.prime != other.prime

    def __iadd__(self, other):
        return self + other

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError("Field orders must be equivalent for field addition to be valid")
        num = (self.num + other.num) % self.prime
        return FieldElement(num, self.prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError("Field orders must be equivalent for field subtraction to be valid")
        num = (self.num - other.num) % self.prime
        return FieldElement(num, self.prime)

    @methdispatch
    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError("Field orders must be equivalent for field multiplication to be valid")
        num = (self.num * other.num) % self.prime
        return FieldElement(num, self.prime)

    @__mul__.register(int)
    def _(self, other):
        num = (self.num * other) % self.prime
        return FieldElement(num, self.prime)

    def __pow__(self, exponent):
        num = pow(self.num, exponent, self.prime)
        return FieldElement(num, self.prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError("Field orders must be equivalent for field division to be valid")
        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        return FieldElement(num, self.prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return FieldElement(num, self.prime)

    def sqrt(self):
        return self**((P + 1) // 4)
