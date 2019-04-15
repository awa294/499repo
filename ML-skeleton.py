import numpy as np
import csv 
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score 
from sklearn.metrics import f1_score 
from sklearn.metrics import precision_score 
from sklearn.metrics import recall_score
from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn import tree
from sklearn.neural_network import MLPClassifier
import matplotlib.pyplot as plt


df = pd.read_csv("all_traffic.csv")
#print(df[:10])
# You might not need this next line if you do not care about losing information about flow_id etc. All you actually need to
# feed your machine learning model are features and output label.
columns_list = ['tran_proto', 'avg_sent_len', 'avg_rec_len', 'avg_sent_ttl', 'average_rec_ttl', 'label']
df.columns = columns_list
features = ['tran_proto', 'avg_sent_len', 'avg_rec_len', 'avg_sent_ttl', 'average_rec_ttl']

X = df[features]
y = df['label']

acc_scores = 0
acc_results = np.array([])
prec_results = np.array([])
rec_results = np.array([])
f1_results = np.array([])
for i in range(0, 10):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25)
    
    #Decision Trees
    #clf = tree.DecisionTreeClassifier()
    #clf.fit(X_train, y_train)

    # Neural network (MultiPerceptron Classifier)
    #clf = MLPClassifier()
    #clf.fit(X_train, y_train)

    #SVM's
    clf = SVC(gamma='auto')     #SVC USE THIS
    clf = LinearSVC()  #Linear SVC
    clf.fit(X_train, y_train) 


    #here you are supposed to calculate the evaluation measures indicated in the project proposal (accuracy, F-score etc)
    #acc_result = clf.score(X_test, y_test)  #accuracy score 
    y_pred = clf.predict(X_test)
    #prec_result = precision_score(y_test, y_pred, average="micro")
    #rec_result = recall_score(y_test, y_pred, average="micro")
    f1_result = f1_score(y_test, y_pred, average="micro")
    #prec_results = np.append(prec_results, prec_result)
    #acc_results = np.append(acc_results, acc_result)
    #rec_results = np.append(rec_results, rec_result)
    f1_results = np.append(f1_results, f1_result)
    #print(acc_result)
    #print(prec_result)
    #print(rec_result)
    #print(f1_result)

#print(results)
#print("Average Scores:")
#avg= np.average(acc_results)
#p_avg = np.average(prec_results)
#r_avg = np.average(rec_results)
f_avg = np.average(f1_results)
#print("Accuracy:")
#print(avg)
#print("Precision:")
#print(p_avg)
#print("Recall:")
#print(r_avg)
print("F1:")
print(f_avg)
