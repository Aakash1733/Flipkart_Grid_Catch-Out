from git import Repo
import os
from flask import Flask,render_template,url_for,request,redirect,send_file,make_response
import shutil
import json
import csv
import pandas as pd
import plotly_express as px
from prettytable import PrettyTable
import plotly
import pdfkit
from matplotlib.pyplot import legend
import nvdlib
import plotly.graph_objects as go
import stat
import requests,zipfile
from io import BytesIO
import wget

def addjscon(): 
 os.system("python -m pipreqs.pipreqs fgh --force --savepath fgh//requirements.txt --encoding=utf8")
 os.getcwd()
 path=os.path.join('fgh')
# change the directory path folder name according to your directory
 os.chdir(path)
 os.system("npm list --json>temp.json")

 f = open("temp.json","r")
 w=open("requirements.txt","a+")
 data = json.load(f)
 try:
  dependencies=data["dependencies"]
  f.close()
  for (x) in dependencies:
    w.writelines(x+"\n")
  w.close()  
 except:
    pass
def downloadgit(link):
    ##link="https://github.com/par2909/par2909-campaign_crowdFunding.git"
    os.mkdir('fgh')
    folder="fgh"
    Repo.clone_from(link,folder)
    addjscon()
def downloadpip(name):
    ##name="download"
    os.mkdir('fgh')            
    os.system("pip install --target=fgh "+name+" --no-user --upgrade")                                          ##download pypi package
    addjscon()
def downloadother(link):
    filename = link.split('/')[-1]
    req = requests.get(link)
    zippi= zipfile.ZipFile(BytesIO(req.content))
    os.mkdir('fgh')
    zippi.extractall('fgh')
    addjscon()
def delete(path):
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            filename = os.path.join(root, name)
            os.chmod(filename, stat.S_IWUSR)
            os.remove(filename)
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir('./'+path)   
    """path could either be relative or absolute. """
    # check if file or directory exists
    #if os.path.isfile(path) or os.path.islink(path):
        # remove file
    #    os.remove(path)
    #elif os.path.isdir(path):
        # remove directory and all its content
         #shutil.rmtree(path)
    #else:
    #    raise ValueError("Path {} is not a file or dir.".format(path))
def nvd():
    fetchFile=r"fgh\requirements.txt"
    writeFile="temp_result.txt"
    # wf=open(writeFile,"wt")

    count=0
    score=0
    cHIGH=0
    cLOW=0
    cMEDIUM=0
    cCRITICAL=0
    cV2=0
    cV3=0
    tempV2=0
    tempV3=0

    header=["Header_Name","CVE_ID","CVE_Score","CVE_URL","Severity"]
    k=open("cve.csv","w+")
    writer=csv.writer(k)
    writer.writerow(header)


    with open(fetchFile,"r") as fp:
      line = fp.readline()
      while line:
       if line.rstrip():
        r= nvdlib.cve.searchCVE(keyword =line, key='4a60459b-5b83-4e00-87bc-aebc5064af83', limit=100)
        #print(line)
        tempV2=0
        tempV3=0
        for eachCVE in r:
            #print(eachCVE.id, eachCVE.score, eachCVE.url)
            line=line.rstrip()
            writer.writerow([line,eachCVE.id, eachCVE.score, eachCVE.url,eachCVE.score[2]])
            if(eachCVE.score[0]=='V2'):
                cV2=cV2+1
                tempV2=tempV2+1
            if(eachCVE.score[0]=='V3'):
                cV3=cV3+1
                tempV3=tempV3+1

            if (eachCVE.score[2]=='LOW'):
                cLOW=cLOW+1
            if(eachCVE.score[2]=='MEDIUM'):
                cMEDIUM=cMEDIUM+1
            if(eachCVE.score[2]=='HIGH'):
                cHIGH=cHIGH+1
            if(eachCVE.score[2]=='CRITICAL'):
                cCRITICAL=cCRITICAL+1
            if(eachCVE.score[1]!=None):
                score=score+eachCVE.score[1]
                count=count+1
       line = fp.readline()
    fp.close()    
    if os.path.getsize("cve.csv") == 0:
        dff=pd.read_csv("demo1.csv")
    else:
        dff=pd.read_csv("cve.csv")
    dff.head()
    #print(dff.shape)
    df = dff.dropna()
    fig1 = px.histogram(df, x='Header_Name',color='Severity',barmode='group', width=600, height=400)
    graph11JSON=json.dumps(fig1,cls=plotly.utils.PlotlyJSONEncoder)
    #fig1.show()
    if count !=0:
     fscore=12-score/count
    else:
        fscore=10
    labels = ['Low','Medium','High','Critical']
    values = [cLOW, cMEDIUM, cHIGH, cCRITICAL]
    fig4 = px.pie(names=labels,values=values,template='plotly_dark', width=500, height=500)
    fig4.update_traces(hoverinfo='label+percent', textinfo='value+label', textfont_size=10 , title="Severity",titlefont_size=20)
    graph12JSON=json.dumps(fig4,cls=plotly.utils.PlotlyJSONEncoder)
    #fig4.show()
    fig = go.Figure(go.Indicator(mode = "gauge+number",value = fscore,domain = {'x': [0, 1], 'y': [0, 1]},gauge = {'axis': {'range': [None, 10]},'bar': {'color': "darkblue"},'steps' : [{'range': [0, 5], 'color': "red"},
                    {'range': [5, 10], 'color': "green"}]}))
    fig.update_layout(font = {'color': "darkblue", 'family': "Arial" , 'size':20},width=350,height=350,margin=dict(t=0, b=0, l=0, r=0))
    graph13JSON=json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)
    #fig.show()
    #print("Score : ",score/count)
    #print("V2:",cV2," , V3:",cV3)
    nvdlist=("LOW:"+str(cLOW)+",MEDIUM:"+str(cMEDIUM)+",HIGH:"+str(cHIGH)+",CRITICAL:"+str(cCRITICAL))
    return graph11JSON,graph12JSON,graph13JSON,nvdlist
def jsonfile():
 path=os.getcwd()
# path=os.path.join('ApplicationInspector-main')
 os.chdir(path)
 os.chdir('../')

 file="fgh"
 print("Current working directory: {0}".format(os.getcwd()))
 resultFile="output.json"
# os.system("AppInspector analyze -s D:\solidity_remixIDE\campaign_react_code_updated -f json -o output.json")
 os.system("AppInspector analyze -s " + file + " -r back_door2.json -f json -o " + resultFile+" -g **/tests/**,**/.git/**")
 return

def filehandle():         
 f=open("result.csv","w+")
 writer = csv.writer(f)
 print("Current working directory: {0}".format(os.getcwd()))
 jsonFile="output.json"
 if os.path.getsize("output.json") == 0:
    jsonFile="demo1.json"
 df=pd.read_json(jsonFile)
 k=df['metaData']
 l=k['detailedMatchList']
 if(k['totalMatchesCount']>0):
  df2=pd.DataFrame(l)
  dataframe = pd.DataFrame().assign(Rule_ID=df2['ruleId'],Rule_Name=df2['ruleName'],Rule_Description=df2['ruleDescription'],
    Tag=df2['tags'],Sample=df2['sample'],Severity=df2['severity'],Pattern=df2['pattern'],Confidence=df2['confidence'],Type=df2['type'],Language=df2['language'],Filename=df2['fileName'])
 else:
    dk=pd.read_json("demo1.json")
    k=dk['metaData']
    l=k['detailedMatchList']
    df2=pd.DataFrame(l)
    dataframe=pd.DataFrame().assign(Rule_ID=df2['ruleId'],Rule_Name=df2['ruleName'],Rule_Description=df2['ruleDescription'],
    Tag=df2['tags'],Sample=df2['sample'],Severity=df2['severity'],Pattern=df2['pattern'],Confidence=df2['confidence'],Type=df2['type'],Language=df2['language'],Filename=df2['fileName'])
 
 fig4 = px.pie(dataframe,names=dataframe.Severity.value_counts().index,values=dataframe.Severity.value_counts()
 ,template='plotly_dark', width=300, height=300)
 fig4.update_traces(hoverinfo='label+percent', textinfo='percent', textfont_size=10 ,titlefont_size=20,automargin=True)
 graph1JSON=json.dumps(fig4,cls=plotly.utils.PlotlyJSONEncoder)



 fig = px.histogram(dataframe, x='Language', color="Language",title="Code Language Type",template='plotly_dark', height=400,width=600).update_xaxes(categoryorder='total descending') 
 graph2JSON=json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)
 
    # Write to a CSV file
 #print((dataframe['Severity'].value_counts()/dataframe['Severity'].count())*100)
 dff=dataframe.query('Severity=="Critical"',inplace=False)
 bb=dataframe.query('Severity=="Important"',inplace=False)
 if len(dff)>10:
    star=1
    usability= "NOT USABLE"
    vulner= "The below 10+ CRITICAL vulnerabilities are found in the following files of the repository.Refer to the table for more information"
 elif len(dff)!=0:
    usability="Usable (With Slight Modifications)"
    vulner= "The below CRITICAL vulnerabilities are found in the following files of the repository . KINDLY RESOLVE THEM BEFORE USING"
    if len(bb)>10:
        star=2
    elif len(bb)!=0:
        star=3
    else :
        star=4
 else:
    star=5
    usability="Healthy and Usable"
    vulner="The Code has NO CRITICAL vulnerability and can be used after rectifying so issues as listed below"
# Separating the Headers
 l1 = list(dataframe.columns)
 
# headers for table
 t = PrettyTable([l1[0],l1[1],l1[2], l1[3],l1[4], l1[5], l1[6],l1[7], l1[8],l1[9], l1[10]])
 
# Adding the data
 for i in range(0, len(dff)) :
    t.add_row(dff.iloc[i])
 code = t.get_html_string()
 html_file = open('Tablee.html', 'w')
 html_file = html_file.write(code)
 dataframe.to_csv("result.csv")
 return graph1JSON,graph2JSON,code,usability,vulner,star
    
app=Flask(__name__,template_folder="templates")
@app.route('/',methods=['POST','GET'])
def home():
    value1=request.form.get('directory')
    value2=request.form.get('link')
    if value1=="1":
        delete('fgh')
        downloadgit(value2)
        return redirect(url_for('index'))
    elif value1=="3":
        delete('fgh')
        downloadpip(value2)
        return redirect(url_for('index'))
    elif value1=="4":
        delete('fgh')
        downloadother(value2)
        return redirect(url_for('index'))
    value3=value1
    value4=value2
    return render_template('main.html',value3=value3,value4=value4)
@app.route('/index',methods=['GET','POST'])
def index():
    jsonfile()
    graph1JSON,graph2JSON,code,usability,vulner,star=filehandle()
    graph11JSON,graph12JSON,graph13JSON,nvdlist=nvd()
    # return render_template('index.html',graph1JSON=graph1JSON,graph2JSON=graph2JSON,code=code,usability=usability,vulner=vulner,graph3JSON=graph13JSON,graph11JSON=graph11JSON,graph12JSON=graph12JSON,nvdlist=nvdlist,star=star)
    file=render_template('index.html',graph1JSON=graph1JSON,graph2JSON=graph2JSON,code=code,usability=usability,vulner=vulner,graph3JSON=graph13JSON,graph11JSON=graph11JSON,graph12JSON=graph12JSON,nvdlist=nvdlist,star=star)
    with open('report.html', 'w') as f:
        f.write(file)
    return file

@app.route('/download')
def download_file():
	path = "../application/result.csv"
	return send_file(path, as_attachment=True)
@app.route('/downloadit')    
def download_dependency():
	path = "../application/cve.csv"
	return send_file(path, as_attachment=True)

@app.route('/download2')
def report():
    path = "report.html"
    return send_file(path, as_attachment=True)
app.run(host='localhost',port=5000)
