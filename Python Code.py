
"""
Created on Tue Feb 22 00:10:46 2022

@author: Barclay Cousin - B1037353

The cleaning and visualisation of KDD 1999 dataset. ICA 1
"""



# Importing modules - pandas and matplotlib 
import pandas as pd
import matplotlib.pyplot as plt


print("Starting...")

# Creating a variable with the name of the datafile and its location
file_path = 'kddcup.data_10_percent_corrected.csv'

# Reading the dataframe file and showcasining there is no headers
df = pd.read_csv(file_path, header=None)

# Listing and adding all of columns - attack_type added 
df.columns = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","attack_type"]
              


# This is a function created to stop dupliation of code, this allows for easy viewing of data when called
def seperate():
    print("\n", "-" * 70, "\n")

print('Processing Data...')
seperate()


# This exploratory analysis is used to find the first 6 columns 
#pd.set_option('display.max_columns', 500) - Note: I tried adding this to showcase all columns but 
# effected user visibility and the overall look of outputted data
print("The top 6 results of the dataframe are:\n",df.head(6))
seperate()

# This exploratory analysis is used to find the last 2 columns 
print("The bottom two results of data are:\n",df.tail(2))
seperate()


print("A description of the dataset:\n", df.describe)
seperate()

print(df.mode)

# This is showcasing the amount of columns within the dataframe
print('There are',len(df.columns), 'columns in this dataframe')
seperate()
    

# This analysis finds out all the unique elements within a column to see for any anamoly data such as string values
print("The unique attack types are as follows", df['attack_type'].unique())
seperate()

# Output of the mean duration
print("The average duration of the connection was", df['duration'].mean())
seperate()

print("The median duration of a connection was", df['duration'].median(), "this was due to the mass amount of zero's within the dataframe.")
seperate()

print('Different types of network service on the destination are:\n\n',df['service'].unique())
seperate()

# Finding out the length of the dataframe 
print("The total amount of rows in the dataframe is", len(df['num_compromised']))
seperate()

# Outputting all of the first record.
print("Output of the entirety of the first record:\n\n",df.loc[0])
seperate()

print("The total number of files accessed is", df['num_access_files'].sum())
seperate()

print("The total number of of compromises is", df['num_compromised'].sum())
seperate()

print("The amount of times root shell was obtained was", df['root_shell'].sum(),"times")
seperate()
print("Output of what the labels for the protocol pie chart - biggest to largest:\n", 
      df["protocol_type"].value_counts())
seperate()

print("Generating the labels for the logged in pie chart:\n", df['logged_in'].value_counts())
seperate()


print("Generating Charts...")
seperate()



# Logged in - Bar Chart
c = ['red', 'blue']
# If user is succesfully logged in bar chart 
logeed_in_bar_chart = df['logged_in'].value_counts()
logeed_in_bar_chart.plot(kind='bar', color =c)
plt.xlabel('1 is equal to succesfully logged in, 0 is otherwise')
plt.ylabel('Amount of attempts ')
plt.title('Visual Representation of if Attacks Were Able To Succesfully Log in or Not', fontsize=12)
plt.grid()
plt.show()




# Protocol Type used - Bar chart
protocol_type_bar_graph = df['protocol_type'].value_counts()
protocol_type_bar_graph.plot(kind='bar', color = c)
plt.xlabel('Protocol Used')
plt.ylabel('Amount of Times Used ')
plt.title('Bar Chart Visualisation For Protocol Type', fontsize=15)
plt.show()

# Attack Type - Bar chart
plt.figure(figsize=(18,7))
attack_type_bar_graph = df['attack_type'].value_counts()
plt.yscale('log')
attack_type_bar_graph.plot(kind='bar')
plt.xlabel('Attack Type')
plt.ylabel('Amount - 10 to the power of 5 = 100 thousand')
plt.title('Amount of times Attack An Type Has Been Used', fontsize=15)
plt.grid()
plt.show()


# Number of files accessed and duration line chart. 
plt.figure(figsize=(12,4)) 
plt.plot(df['num_access_files'], df['duration'])
plt.grid(linewidth=1)
plt.xticks(rotation=10)
plt.yticks(rotation=10)
plt.title("Line Chart Visualisation For Number of Files Accessed Against Duration")
plt.ylabel("Duration - Seconds")
plt.xlabel("Files Accessed")
plt.show()

# Duration and file creation scatter graph. 
plt.figure(figsize=(12,4)) 
plt.scatter(df['num_file_creations'], df['duration'])
plt.ylabel("Duration - Seconds")
plt.xlabel("Number of Files Created")
plt.title("Scatter Graph Showcasing Files Created Against Time")
plt.show()


# Pie Chart for Protocol type used 
labels = 'ICMP', 'TCP', 'UDP'

plt.figure(figsize=(6,6))
explode = (0.05, 0.0, 0)
plt.pie(df["protocol_type"].value_counts(),autopct='%1.1f%%',
        shadow=True,explode=explode, startangle=90, labels=labels)
plt.tight_layout()
plt.legend()
plt.title("Pie Chart Visualisation For Protocol Type Used", fontsize=14)
plt.show

# Logged in - Pie chart with labels 
x = ['unsuccessfully Logged in', 'Successfully Logged in']
plt.figure(figsize=(6,6))
explode = (0.05, 0.0)
plt.pie(df["logged_in"].value_counts(),autopct='%1.1f%%',
        shadow=True,explode=explode, startangle=90, labels=x)
plt.tight_layout()
plt.legend()
plt.title("Pie Chart Visualisation For Succesful Log ins", fontsize=14)
plt.show

# Final output
print("The Process is now complete!")
































# I believe this needs some work - what is the duration bit showing 
# x= df['attack_type']
# y = df['duration']
# # Plotting
# print("startining again...")
# plt.bar(x, y)
# plt.show()

# print("done")



# I think this is the amount of times this attack has been used
# plt.figure(figsize=(30,20))
# class_distribution = df['attack_type'].value_counts()
# class_distribution.plot(kind='bar')
# plt.xlabel('Class')
# plt.ylabel('Data points per Class')
# plt.title('Distribution of yi in train data')
# plt.grid()
# plt.show()


'''

This is a pie chart and the settings needeed 



'''
#class_distribution = df['attack_type'].value_counts()


# #Pie Chart
# my_labels = 'normal', 'perl', 'loadmodule', 'buffer_overflow'
# index = my_labels
# plt.pie(class_distribution, labels=my_labels, wedgeprops={'edgecolor': 'red'})
# plt.title('My Tasks')
# plt.axis('equal')
# plt.show()



# Kind of bar chart 
# plt.clf()
# plt.figure(figsize=(12,8))
# params = {'axes.titlesize':'18',
#           'xtick.labelsize':'14',
#           'ytick.labelsize':'14'}
# matplotlib.rcParams.update(params)
# plt.title('Distribution of attacks')
# #df.plot(kind='barh')
# df['attack_type'].value_counts().plot(kind='barh')

# plt.show()


# UNCOMMENT THIS ONE! 
# plt.figure(figsize=(30,20))
# class_distribution = df['logged_in'].value_counts()
# class_distribution.plot(kind='bar')
# plt.xlabel('Class')
# plt.ylabel('Data points per Class')
# plt.title('Distribution of yi in train data')
# plt.grid()
# plt.show()

# plt.figure(figsize=(15,7))
# class_distribution = df['attack_type'].value_counts()
# class_distribution.plot(kind='bar')
# plt.xlabel('Class')
# plt.ylabel('Data points per Class')
# plt.title('Distribution of yi in train data')
# plt.grid()
# plt.show()


















