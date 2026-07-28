# VS Code
```
# Extensions:
Python
autopep8				# for formatting the document, open command palate and run Format Document
File > Preferences > Settings > Format On Save (enable)			# for autopep8 formatting to work after each save

# Keyboard shortcuts
ctrl + `				# Open and close the terminal
ctrl + shift + M			# Problems
ctrl + shift + P			# Command Palate
ctrl + /				# comment/uncomment the selected lines
F2					# rename/refactor all references

# Creating custom keyboard shortcuts
ctrl + shift + P > Preferences: Open Keyboard Shortcuts > Python: Run Python File (this is a command that we want to add a shortcut for it)

```

# Primitive Types

```
strings = "Hello World!"
number = 123
boolean = True/False

```

===============================================================================

# Built-in Functions
```
Print("Text")				# Print the string
Print(some_var)				# Print the variable

input()					# Get the input of user (always returns an string)
input("Name: ")				# Ask user to enter their name

type(some_var)				# type of the variable

ord("b")				# numeric value of a letter (ASCII)
``` 

===============================================================================

# Strings
```
-----------------------
# Basics

"Alice" + "Bob" 			# AliceBob
"Alice" + " Bob" 			# Alice Bob
"Alice" * 3				# AliceAliceAlice
"Alice" + "!" * 10			# Alice!!!!!!!!!!
f'Some string {variable}'		# Format String (adding variable in string)
f"{first_name} {last_name}"		# Naqib Amini
f"{len(first_name)} {2 + 2}"		# 5 4
sites = some_string.split(',')		# split the variable (string) into a list based on commas (,)

course = "Python Programming"
print(course[0])			# P
print(course[-1])			# g
print(course[0:3])			# Pyt (not include the index 3 - from 0 to 2)
print(course[:3])			# Pyt (not include the index 3 - from 0 to 2)
print(course[:-1])			# Python Programmin (not include the index -1)
print(course[0:])			# Python Programming
print(course[:])			# Python Programming

-----------------------
# Multi Line String

mutli_line_string = """
Dear Python,

I am learning you today!

Please be nice!

Best,
Me
"""

-----------------------
# Iterable

# String is iterable, which means we can use it in for loop

for x in "Python":
    print(x)				# P; y; t; h; o; n

-----------------------
# Escape Sequences

Escape Character = \
Escape Sequences = \" ("), \' ('), \\ (\),\n (new line)

-----------------------
# Functions and Methods

course = "Python Programming"
print(len(course))			# 18

# Everything in python is an object and objects have functions that we call methods and we can access them using the dot notation.

print(course.upper())			# PYTHON PROGRAMMING
course.lower()				# Lower case all charecters
course.title()				# Capitalize the first character of each word
course.strip()				# Remove the white spaces at the begening and the end of the string
course.rstrip()				# Right strip
course.lstrip()				# Left strip
course.replace("P", "j")		# replace all P with j
course.find("Pro")			# find the index of the search param
print(course.find("Pro"))		# 7
"Pro" in course				# True/False, if "Pro" is in the course var
"Pro" not in course			# True/False, if "Pro" is not in the course var

message.split(' ')			# convert the string to list and use the space as delimiter
```

===============================================================================

# Numbers
```
-----------------------
# Types

x = 1					# Integer
x = 1.1					# Float
x = 1 + 2j				# Complex Number (a + bi)	

-----------------------
# Operations

2 + 2					# Addition
10 - 3					# Subtraction
10 * 3					# Multiplication
10 / 3					# Division (Float result, 3.333333333333)
10 // 3					# Division (Integer result, 3)	
10 % 3					# Modulus (remainder of a division)
10 ** 3					# Exponent (10 to the power of 3)

-----------------------
# Augmented Assignment Operator	

# Simple
x = 10
x = x + 3

# AAO
x += 3

-----------------------
# Functions and Methods

round(2.9)				# 3
abs(-2.9)				# 2.9 (absolute value)

# For more methods, import math

import math

math.ceil(2.2)				# 3 (get ceiling of a number)

```

===============================================================================

# List
```
-----------------------
# Basics
names = ["John", "Bob", "Mosh", "Sarah", "Mary"]
print(names)				# ['John', 'Bob', 'Mosh', 'Sarah', 'Mary']

names[0] = 'Jon'
print(names)				# ['Jon', 'Bob', 'Mosh', 'Sarah', 'Mary']

print(names[0])				# Jon
print(names[-1])			# Mary
print(names[0:4])            		# prints a new list; does not include 4th index

print(names[0:3])			# ['Jon', 'Bob', 'Mosh'] (not include the index 3 - from 0 to 2)
print(names[:3])			# ['Jon', 'Bob', 'Mosh'] (not include the index 3 - from 0 to 2)
print(names[:-1])			# ['Jon', 'Bob', 'Mosh', 'Sarah'] (not include the index -1)
print(names[0:])			# ['Jon', 'Bob', 'Mosh', 'Sarah', 'Mary']
print(names[:])				# ['Jon', 'Bob', 'Mosh', 'Sarah', 'Mary']

-----------------------
# unpacking a list 

numbers = [1, 2, 3]
x, y, z = numbers			# x=1, y=2, z=3


-----------------------
# 2D List

# list in list

atrix = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]

print(matrix[0][1])			# 2

matrix[0][1] = 20
print(matrix[0][1])			# 20

for row in matrix:
    for item in row:
        print(item)			# 1; 20; 3; ...; 9

-----------------------
# list methods and functions

numbers = [5, 2, 1, 7, 4]

# Below methods will change the original list
numbers.append(20)			# add to the end of the list
numbers.insert(0, 10)			# insert(index, value), insert the value at specific index in the list
numbers.remove(5)			# remove 5 from the list
numbers.clear()                 	# clear everything from the list
numbers.pop()				# remove the last number from the list
numbers.sort()				# sort the list
numbers.reverse()			# reverse the list from last index to first index
numbers.copy()				# copy the original list

# Below methods will not change the original list, but return a value;
# returns the index of first 5 on the list; 
# get and error if the value (5) doesn't exist in the list
print(numbers.index(5))	

# below will return True or False, (no error if the value doesn't exist in the list)
print(50 in numbers)

sum(numbers)				# sum up the numbers in the list
len(numbers)				# give you the length of the list (total count of items)

-----------------------
# Copy the list in memory for loops

---
# numbers.remove will remove the item from the list and change the original list immediately;
# the second index becomes the first index;
# for loop skips the first index because it already went trough that
 
numbers = [5, 2, 1, 7, 4]

for number in numbers:
    numbers.remove(number)

print(numbers)				# result: [2, 7]


---
# for loop gets its own copy of the list;
# the original list will change, but the copy will stay the same;
# loop will iterate over the copy;

numbers = [5, 2, 1, 7, 4]

for number in numbers[:]:
    numbers.remove(number)

print(numbers)				# result: []
```

===============================================================================

# Tuples
```
# we can not change or modify tuples (immutable)

numbers = (1, 2, 3)

# the square bracket indexing will work same as list
print(numbers[0])			# 1

-----------------------
# unpacking the tuple 

numbers = (1, 2, 3)
x, y, z = numbers			# x=1, y=2, z=3

-----------------------
numbers.count()
numbers.index()

-----------------------
# single element tuple

(1,)					# this is a tuple with single element

---
cords = (1, 2, 3)
print(cords[0:1])			# result: (1,)

---
type((1))    				# int
type((1,))	  			# tuple

```

===============================================================================

# Dictionaries
```
# key:value pairs
# keys should be unique
# keys must be immutable (hashable) types. (str, int, float, tuple - if contain immutable items, bool)
# value can be any type

customer = {
    "name": "John Smith",
    "age": 30,
    "is_verified": True
}

print(customer["name"])					# error if the key doesn't exist
print(customer.get("name"))         			# None, if the key doesn't exist
print(customer.get("Title", "Defaul Job"))         	# Default value

customer["name"] = "Jack Smith"                     	# edit a key
customer["birthdate"] = "Jan 1 1919"                	# add to dict
print(customer.get("name"))
print(customer.get("birthdate"))
```

===============================================================================

# Functions
```
# print(), round(), etc. are built int functions
# We can create out own custom functions

-----------------------
# Basic

def greet():				# define a function
    print("Hi there")
    print("Welcom aboard")


greet()					# run the function

-----------------------
# Arguments

def greet(first_name, last_name):		# the two inputs for function are called Parameters
    print(f"Hi {first_name} {last_name}")	# by default all the Parameters are required
    print("Welcom aboard")


greet("Naqib", "Jan")				# the values we pass to the function are called Arguments
greet("John", "Smith")				# we can call it with different arguments (reusable)

-----------------------
# Types of Functions

# 1- Perform a task (like print)
# 2- Return a value (like round)


# 1- Perform a task, in this case print a value in the terminal
def greet(name):
    print(f"Hi {name}")

# 2- Return a value, in this case simply return the value and not printing it in the terminal for users
def get_greeting(name):
    return f"Hi {name}"

# None: In python all function return None by default (we will see the None on the output of functions that performs a task)
print(greet("Mosh"))			# Hi Mosh; None

# If the function returns a value, then it is return its value instead of None
print(get_greeting("Mosh"))


-----------------------
# Keyword Arguments

def increment(number, by):
    return number + by


resutl = increment(2, by=1)		# we can optionally add by=1 for more readability
print(resutl)

-----------------------
# Default Value 

# The default value will be passwd if no argument was passed for it
# Adding a default value makes a parameter to be optional
# All optional parameters must be added after all required parameters at the end
def increment(number, by=1):		
    return number + by


print(increment(2))			# result = 3
print(increment(2, 6))			# result = 8


-----------------------
# *args (xargs)

# Sometimes a function takes a variable number of arguments instead of a set predicted number of arguments

---
# Example 1:
def multiply(*numbers):			# run the function against all the of the passed arguments 
    print(numbers)			# print all the arguments (inside a tuple)


multiply(2, 3, 4, 5)			# result: (2, 3, 4, 5)

---
# Example 2:

def multiply(*numbers):
    total = 1
    for number in numbers:
        total *= number
    return total


print(multiply(2, 3, 4, 5))		# result: 120
```

===============================================================================

# Classes
```
# Everything in Python is an object (str, int, list, etc.)

# Classes define new object types (templates), and objects are instances of classes

# Functions inside a class are called methods
# Methods are called using dot notation with () → obj.method()
# Attributes are accessed using dot notation without () → obj.attribute

# Attributes are variables that belong to a specific object (instance)

# point1 = Point() creates an instance (object) of the Point class
# The created object is assigned to the variable point1

# (self) refers to the current instance (the object calling the method)
# It usually refers to the same object stored in a variable (like point1)
# Basically, self is a parameter that represents the object (instance) calling the method

-----------------------
# Basics 

class Point:                		# Pascal naming convention (capitalize the first letter of each word)
    def move(self):			# This is a method inside the class
        print("move")

    def draw(self):
        print("draw")


point1 = Point()			# Creating an object (an instance of the class) and store it in point1
point1.draw()				# Calling the draw method for the point1 object
point1.x = 10				# Creating the attribute/variable "x" for the point1
print(point1.x)

-----------------------
# Constructor

# Constructor is the function that is called at the time of creating the object
# The method with "__init__" that gets called when we create a new point object

class Point:
    def __init__(self, x, y):		# This is the constructor method (x, and y are parameters)
        self.x = x			# self.x and self.y are attributes (stored on the object/instance)
        self.y = y			# x and y (right side) is the parameter holding the argument value


point = Point(10, 20)			# 10 and 20 are the arguments
print(point.x)				# 10
point.y = 30				# we can also update the values
print(point.y)				# 30

-----------------------
# Inheritance
class Mammal:
    def walk(self):
        print("walk")


class Dog(Mammal):			# Dog class can use all methods in Mammal class
    def bark(self):
        print("bark")


class Cat(Mammal):
    pass				# if the child class doesn't have any method, then "pass"

```

===============================================================================

# Type Conversion
```
-----------------------
# Example:

x = input ("x: ")			# Always returns an string
y = int(x) + 1				# convert x to int (This is not changing the type of the original x variable, only changing the type in y)
x = int(x)				# Changes type of the variable x (x is an integer after this)
print(type(x))				# print the type of the x
print(f"x: {x}, y: {y}"}		# format the string

-----------------------
# Types

int(x)
float(x)
bool(x)
str(x)

# range

-----------------------
# Boolean type conversion

# Falsy: These have the value of False when converting or using as Boolean

""
0
None

bool(0)					# False
bool("")				# False
bool(None)				# False

# Truety: Everything else is has the value of True when converted or used as Boolean

bool("an string")			# True
bool(-1)				# True
```

===============================================================================

# Comparison Operators
```

10 > 3					# True
30 >= 3					# True
10 < 3					# False
10 <= 20				# True
10 == 10				# True
10 == "10"				# False
10 != 3					# True
"bag" > "apple"				# True, b comes after a
"bag" == "BAG"				# False, b=98, B=66

-----------------------
# Chaining Comparison Operators

age = 22
18 <= age < 65
```

===============================================================================

# Conditional Statements
```
if temperature > 30:
    print("It's warm")
elif temperature > 20:
    print("It's nice")
else:
    print("It's cold")
```

===============================================================================

# Ternary Operator
```
# Simple
age = 22
if age >= 18:
    message = "Eligible"
else:
    message = "Not eligible"

# Ternary
message = "Eligible" if age >= 18 else "Not eligible"

# Print
print(message)
```

===============================================================================

# Logical  Operator
```
# and, or, not

high_income = False
good_credit = True
student = False

# to print "Eligible", either high_incom or good_credit should be true, and the user must not be an student 
if (high_income or good_credit) and not student:
    print("Eligible")
else:
    print("Not eligible")

-----------------------
# Prompt Example 1:

command = ""
while command != "quit" and command != "QUIT":
    command = input(">")
    print("ECHO", command)

# input = quit - then - False and True = False
# input = QUIT - then - True and False = False
# input != quit and QUIT - True and True = True

-----------------------
# short-circuit Evaluations

# and: as soon as one condition is False (condition not meet), the evaluation stops
# or: as soon as one condition is True (codition meets), the evaluation stops
```

===============================================================================

# for Loop
```

-----------------------
# Iterables

# in a for loop, we mostly iterating over an iterable object
Types = range, strings, lists, custom objects, ...

-----------------------
for number in range(3):			# range from 0 t 2 (does not include 3)
    print("Attempt", number)		# Attempt 0; Attempt 1; Attempt 2

-----------------------
break					# Use break to stop the loop at any time

-----------------------
# for-else statement
successful = False
for number in range (3):
    print("Attempt")
    if successful:
        print("Successful")
        break
else:
    print("Attempted 3 times and failed")

-----------------------
# Nested Loops

for x in range(5):			# (0, 0); (0, 1); (0, 2); (1, 0); ...
    for y in range(3):
        print(f"({x}, {y})")
```

===============================================================================

# while loop
```
# In a while loop, we mostly evaluating a condition

number = 100

while number > 0:
    print(number)
    number //= 2			# 100; 50; 25; 12; 6; 3; 1

-----------------------
# Prompt Example:

while True:
    command = input(">")
    print("ECHO", command)
    if command.lower() == "quit":
        break
```

===============================================================================

# Modules
```
# A module is a Python file that contains code (functions, classes, variables)

# Modules let us reuse code from other Python files
# They also help organize code by splitting it into smaller, manageable files

-----------------------
# There are two ways to import modules:

---
# Example: a file named converters.py in the same directory

# 1. Import the entire module
import converters

# Access functions using dot notation
converters.kg_to_lbs(5)

---
# 2. Import a specific function from the module
from converters import kg_to_lbs
from converters import kg_to_lbs, lb_to_kg	# import multiple functions

# Call the function directly (no module name needed)
kg_to_lbs(5)

-----------------------
# Python3 Module Index

# Here we can find the existing modules (standard libraries)
https://docs.python.org/3/py-modindex.html

# Python comes with a huge library of modules by default

-----------------------
# Example: Random

import random 

random.random()				# returns a random float between 0 to 1
random.randint(1, 6)			# returns a random int between 1 to 6 

members = [‘John’, ‘Bob’, ‘Mary’]
leader = random.choice(members) 	# randomly picks an item from the list
```

===============================================================================

# Packages
```
# A package is a directory that contains modules (Python files)
# It may include an __init__.py file (used to mark it as a package, especially in older Python versions)

# A module is a single Python file (e.g., sales.py)

-----------------------
# Three ways to import from "ecommerce/sales" module:

---
# Importing the entire module
from ecommerce import sales
sales.calc_shipping()				# calc_shopping() is a function in shipping file

---
# Import the entire module 
import ecommerce.sales
ecommerce.shipping.calc_shopping()		

---
# Importing a specific function from the module
from ecommerce.sales import calc_shipping
calc_shipping()

```

===============================================================================

# PyPI
```
# Includes python packages that we can install using pip

# Examples:
pip install openpyxl
pip uninstall openpyxl
```

===============================================================================

# Files and Directories
```
-----------------------
from pathlib import Path

path = Path("ecommerce")			# Relative path (relative to current path)
print(path.exists())				# return True/False 

---
path2 = Path("emails")
path2.mkdir()					# create the "emails" folder
path2.rmdir()					# remove the "emails" folder

---
path3 = Path()
for file in path3.glob("*.py"):			# look for all .py files on the path
    print(file)


-----------------------
# file
f = open("file_name", "r")
print(f.read())

f = open("demofile1.txt", "a")			# Append to an existing file
f.write("The file will include more text..")
f.close()

f = open("demofile2.txt", "w")			# Creating and writing to a new file
f.write("demofile2 file created, with this content in!")
f.close()


# using with - as
with open(file_path, 'r') as file:
	message = file.read()			# needs print()
```