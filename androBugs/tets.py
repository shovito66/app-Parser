test = {
    "a": {
        "b": [],
        "c": [],
        },
    "x":{
        "p": [],
        "q": [],
    }
}

print(id(test.get("a").get("b")))
print(id(test.get("a").get("c")))
# temp = test.get("a").get("b")
for i in range(4):
    print(i)
    # # temp.append(i)
    # test["a"]["b"].append(i)
    test.get("a").get("b").append(i)

# print(temp)
print(test.get("a").get("b"))