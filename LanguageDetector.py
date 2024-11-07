
English_Words=[]

def get_data():
    dictionary = open('english_words.txt', 'r')

    for word in dictionary.read().split('\n'):
        English_Words.append(word)

    dictionary.close()

def Count_Words(text):
    words = text.upper().split()
    matches = 0

    for word in words:
        if word in English_Words:
            matches += 1
    return matches

def is_Text_English(tex):
    matches = Count_Words(tex)
    if(float(matches) / len(tex.split('\n'))) * 100 >= 80:
        return True
    return False



if __name__ == '__main__':
    get_data()
    plain_text = 'My name is Eduard and I am here to decrypt'
    print(is_Text_English(plain_text))