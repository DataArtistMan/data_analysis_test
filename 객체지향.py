# 객체(object)
# =속성 + 행위

class Student:
    def __init__(self, name, korean, math, english, science):
        self.name = name
        self.korean = korean
        self.math = math
        self.english = english
        self.science = science
    # 동사 + 목적어 : 명령어
    def sum(self):
        return self.korean + self.english + self.science + self.math
    def avg(self):
        return self.sum() / 4
    def print1(self):
        print(self.name, self.sum(), self.avg())

student1 = Student('kim', 45,34,54,2)
# 주어 + 동사 + 목적어 : 주어가 행위를 한다
student1.print1()