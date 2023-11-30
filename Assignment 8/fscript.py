import matplotlib.pyplot as plt
from datetime import datetime
from matplotlib import dates as mdates
from collections import defaultdict
import networkx as nx
import matplotlib.backends.backend_pdf as pdf
from matplotlib.backends.backend_pdf import PdfPages
from collections import Counter

# Function to filter logs by username
def export_file(string):
    if "mborsos" in string:
        return string

# Function to parse relevant information from access logs
def info_parser_IpDate(data_list):
    parsed_data = {}
    if "/~mborsos" in data_list[6]:
        parsed_data["IP"] = data_list[0]
        parsed_data["Page_URL"] = data_list[6]
        date_string = data_list[3].replace("[", "")
        parsed_data["Date"] = date_string
    return parsed_data

# Function to process access logs and return a list of dictionaries
def process_access_logs(access_log_path):
    dict_list = []
    with open(access_log_path, "r") as access_log:
        for log in access_log:
            result = info_parser_IpDate(log.split(" "))
            if result != {}:
                result["Browser"] = broswer_parsing(log)
                result["Date_Month"], result["Date_Time"] = date_parser(result["Date"])
                dict_list.append(result)
    return dict_list

# Function to parse browser information from user agent string
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Browser_detection_using_the_user_agent for reference 
def broswer_parsing(string):
    if "/~mborsos" in string:
        if "Chrome/" in string and "Chromium/" not in string:
            return "Chrome"
        elif "Safari/" in string and ("Chrome/" not in string or "Chromium/" not in string):
            return "Safari"
        else:
            return "Other browser than Chrome/Safari"
    else:
        return "Unknown"

# Function to parse date from string
def date_parser(string):
    aux = string.replace("[", "").split(" ")
    if len(aux) >= 2:
        return aux[0], aux[1]
    else:
        # Handle the case where the split list doesn't have enough elements
        return None, None


# Function to parse error information from log entry
def error_parser(string):
    result = string.split("]")
    return result[0], result[1], result[3], result[4]

# Function to process error logs and return a list of dictionaries
def process_error_logs(error_log_path):
    erro_dict = {}
    erro_list = []
    with open(error_log_path, "r") as error_log:
        for log in error_log:
            result = export_file(log)
            if result:
                erro_dict["Date"], erro_dict["Error_name"], erro_dict["Client"], erro_dict["Error"] = error_parser(result)
                erro_dict["Date"] = erro_dict["Date"].replace("[", "")
                erro_dict["Error_name"] = erro_dict["Error_name"].replace("[", "")
                erro_dict["Client"] = erro_dict["Client"].replace("[", "")
                erro_list.append(erro_dict.copy())
    return erro_list

# Function to plot access timeline
def plot_access_timeline(timeline_dates, timeline_ips):
    fig = plt.figure(figsize=(25, 10))
    plt.plot(timeline_dates, timeline_ips, marker='o', linestyle='-', color='deeppink')
    plt.title('Access Log Timeline')
    plt.xlabel('Date and Time')
    plt.ylabel('IP Address')
    plt.xticks(rotation=45)
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%d-%b %H:%M'))
    plt.tight_layout()
    plt.savefig("/home/mborsos/access_timeline.png", bbox_inches='tight')
    
    return fig

# Function to plot error timeline
def plot_error_timeline(grouped_errors):
    fig = plt.figure(figsize=(25, 10))

    for error, dates in grouped_errors.items():
        plt.plot(dates, [error] * len(dates), marker='o', linestyle='-', label=error)

    plt.title('Error Log Timeline (Grouped by Errors Name)')
    plt.xlabel('Date and Time')
    plt.ylabel('Error')
    plt.xticks(rotation=45)
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%d-%b %H:%M'))
    plt.tight_layout()
    plt.savefig("/home/mborsos/timelines_grouped.png", bbox_inches='tight')

    return fig

def plot_error_ip(grouped_errors):
    fig = plt.figure(figsize=(25, 10))

    # Extract errors and clients from the grouped_errors dictionary
    errors = list(grouped_errors.keys())
    clients = list(grouped_errors.values())

    # Plotting scatter plot for errors and clients
    for i, (error, client_list) in enumerate(zip(errors, clients)):
        plt.scatter([error] * len(client_list), client_list,  marker='o', label=error)

    # Adjust plot settings
    plt.title('Error Log and Client (Grouped by Errors Name)')
    plt.xlabel('Client')
    plt.ylabel('Error')
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()
    plt.savefig("/home/mborsos/timelines_ip.png", bbox_inches='tight')

    return fig


# Function to plot IP address frequency
def plot_ip_frequency(ip_counts):
    fig = plt.figure(figsize=(25, 10))

    ips, counts = zip(*ip_counts.items())

    plt.bar(ips, counts, color='skyblue')
    plt.title('IP Address Frequency')
    plt.xlabel('IP Address')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("/home/mborsos/ip_grouped.png", bbox_inches='tight')

    return fig

# Function to plot each page access frequency
def plot_page_frequency(access_logs):
    fig = plt.figure(figsize=(25, 10))

    # Extract page information and counts from the access logs
    pages = [entry["Page_URL"] if "Page_URL" in entry and len(entry["Page_URL"]) <= 50 else "Query Error or Other" for entry in access_logs]
    counts = Counter(pages)

    plt.bar(counts.keys(), counts.values(), color='skyblue')
    plt.title('Page Access Frequency')
    plt.xlabel('Page URL')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45, ha='right')  # Adjust the rotation and alignment for better visibility
    plt.tight_layout()
    plt.savefig("/home/mborsos/page_access_frequency.png", bbox_inches='tight')

    return fig

def plot_page_ip(access_logs):
    fig = plt.figure(figsize=(25, 10))

    # Extract page information and counts from the access logs
    pages = [entry["Page_URL"] if "Page_URL" in entry and len(entry["Page_URL"]) <= 50 else "Query Error or Other" for entry in access_logs]
    counts = Counter(pages)

    plt.bar(counts.keys(), counts.values(), color='skyblue')
    plt.title('Page Access Frequency')
    plt.xlabel('Page URL')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45, ha='right')  # Adjust the rotation and alignment for better visibility
    plt.tight_layout()
    plt.savefig("/home/mborsos/page_access_frequency.png", bbox_inches='tight')

    return fig

# Function to plot each page access with corresponding browser
def plot_page_browser(access_logs):
    fig, ax = plt.subplots(figsize=(25, 10))

    # Extract page information and browsers from the access logs
    data = [(entry["Page_URL"] if "Page_URL" in entry and len(entry["Page_URL"]) <= 50 else "Query Error", entry["Browser"]) for entry in access_logs]

    # Group data by page URL
    grouped_data = defaultdict(list)
    for page, browser in data:
        grouped_data[page].append(browser)

    # Plotting bar chart
    for i, (page, browsers) in enumerate(grouped_data.items()):
        ax.bar(page, browsers, color='skyblue', label=f'{page}\n{", ".join(browsers)}')

    # Adjust plot settings
    ax.set_title('Page Access with Browser')
    ax.set_xlabel('Page URL')
    ax.set_ylabel('Browser')
    ax.set_xticks(range(len(grouped_data)))
    ax.set_xticklabels(grouped_data.keys(), rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig("/home/mborsos/page_access_browser.png", bbox_inches='tight')

    return fig
    
# Function to plot each page access with corresponding IP addresses
def plot_page_frequency(access_logs):
    fig, ax = plt.subplots(figsize=(25, 10))

    # Extract page information and IP addresses from the access logs
    data = [(entry["Page_URL"] if "Page_URL" in entry and len(entry["Page_URL"]) <= 50 else "Query Error", entry["IP"]) for entry in access_logs]

    # Group data by page URL
    grouped_data = defaultdict(list)
    for page, ip in data:
        grouped_data[page].append(ip)

    # Plotting bar chart
    for i, (page, ips) in enumerate(grouped_data.items()):
        ax.bar(page, ips, color='skyblue', label=f'{page}\n{", ".join(ips)}')

    # Adjust plot settings
    ax.set_title('Page Access with IP Addresses')
    ax.set_xlabel('Page URL')
    ax.set_ylabel('IP Address')
    ax.set_xticks(range(len(grouped_data)))
    ax.set_xticklabels(grouped_data.keys(), rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig("/home/mborsos/page_access_ip.png", bbox_inches='tight')

    return fig

# Function to plot IP and browser diagram
def plot_ip_browser_diagram(grouped_browsers):
    fig = plt.figure(figsize=(25, 10))

    unique_ips = list(grouped_browsers.keys())
    ip_indices = {ip: i for i, ip in enumerate(unique_ips)}

    for ip, browsers in grouped_browsers.items():
        plt.scatter([ip_indices[ip]] * len(browsers), browsers, marker='o', label=ip)

    plt.xticks(list(ip_indices.values()), list(unique_ips))

    plt.title('Diagram: IP Addresses and Browsers')
    plt.xlabel('IP Address')
    plt.ylabel('Browser')
    plt.savefig("/home/mborsos/ip_browser.png", bbox_inches='tight')

    return fig


def save_image(filename, figs): 
     
    p = PdfPages(filename)  
      
    # iterating over the numbers in list 
    for fig in figs:  
        
        # and saving the files 
        fig.savefig(p, format='pdf')  
      
    # close the object 
    p.close()     


def main():
    access_log_path = "/var/log/apache2/access_log"
    error_log_path = "/var/log/apache2/error_log"

    # Process logs
    dict_list = process_access_logs(access_log_path)
    erro_list = process_error_logs(error_log_path)

    fig0, ax0 = plt.subplots(figsize=(25, 10))
    ax0.axis('off')  # Turn off the axis

    # Add text to the figure
    fig0.text(0.5, 0.5, 'This PDF contains the following diagrams:\n1.Access Log Timeline\n2.Error Log Timeline\n3.IP Address Frequency\n4.IP Addresses and Browsers\n5.Page Access with IP Addresses\n6.Page Access Frequency\n7.Page Access with Browser\n8.Error Log and Client', 
         fontsize=20, color='deeppink', ha='center', va='center')

    # Plotting access timeline
    timeline_dates = [datetime.strptime(entry["Date"], "%d/%b/%Y:%H:%M:%S") for entry in dict_list if "Date" in entry]
    timeline_ips = [entry["IP"] for entry in dict_list if "Date" in entry]
    fig1 = plot_access_timeline(timeline_dates, timeline_ips)

    # Plotting error timeline
    timeline_dates_error = [datetime.strptime(entry["Date"], "%a %b %d %H:%M:%S.%f %Y") for entry in erro_list]
    timeline_error = [entry["Error"] for entry in erro_list]
    grouped_errors = defaultdict(list)
    for date, error in zip(timeline_dates_error, timeline_error):
        grouped_errors[error].append(date)
    fig2 = plot_error_timeline(grouped_errors)

    # Plotting IP address frequency
    ip_counts = defaultdict(int)
    for entry in dict_list:
        ip_counts[entry["IP"]] += 1
    fig3 = plot_ip_frequency(ip_counts)

    # Plotting IP and browser diagram
    grouped_browsers = defaultdict(list)
    for entry in dict_list:
        grouped_browsers[entry["IP"]].append(entry["Browser"])
    fig4 = plot_ip_browser_diagram(grouped_browsers)

    # Plot IP address frequency
    fig5 = plot_page_frequency(dict_list)

    fig6 = plot_page_ip(dict_list)

    fig7 = plot_page_browser(dict_list)

    timeline_client_error = [entry["Client"] for entry in erro_list]
    timeline_error = [entry["Error"] for entry in erro_list]

    # Extract the client information before the colon
    timeline_clients = [client.split(":")[0] if ":" in client else client for client in timeline_client_error]

    # Create a dictionary to group errors by client name
    grouped_errors = defaultdict(list)
    for client, error in zip(timeline_clients, timeline_error):
        # Group clients with the same name
        grouped_errors[client].append(error)

    # Plot the error and client information
    fig8 = plot_error_ip(grouped_errors)

    # creating figs list
    figs = [fig0, fig1, fig2, fig3, fig4, fig5, fig6, fig7, fig8]

    # name the Pdf file 
    filename = "timeline_diagrams.pdf"  
    
    # call the function 
    save_image(filename, figs) 

    plt.show()

if __name__ == "__main__":
    main()
