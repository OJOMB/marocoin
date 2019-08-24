from field_element import FieldElement


class Point:
    """models a point on an elliptic curve"""
    def __init__(self, x, y, a, b):
        self.x = x
        self.y = y
        self.a = a
        self.b = b
        if x is None and y is None:
            return
        if y**2 != x**3 + a * x + b:
            raise ValueError(f"({x},{y}) is not on the curve")

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):
            return f"Point({self.x.num}, {self.y.num}, {self.a.num}, {self.b.num}) - (Finite Field order: {self.x.prime})"
        else:
            return f"Point({self.x},{self.y}, {self.a}, {self.b})"

    def __eq__(self, other):
        return (
            self.x == other.x and
            self.y == other.y and
            self.a == other.a and
            self.b == other.b
        )

    def __ne__(self, other):
        return (
            self.x != other.x or
            self.y != other.y or
            self.a != other.a or
            self.b != other.b
        )

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f"Points {self} and {other} are not on the same curve")
        # case when self is at point infinity
        if self.x is None:
            return other
        # case when other point is at infinity
        if other.x is None:
            return self
        # case when vertical line intersects once
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        # case when line intersects twice
        if self == other:
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        # case when vertical line intersects twice
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)
        # case when line intersects thrice
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient):
        """coefficient * self"""
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result
