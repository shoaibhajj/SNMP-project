package snmpproject;


import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


class resualt {
    static String  l1,l2,l3,l4,l5,l6,l7,l8,l9,l10,l11,l12,l13;
}
public class Snmpproject implements Runnable {
    static   String name,pass,ip ,port;
    static   int security,hash;
    static  boolean pause =false;
    static List<SNMPHost> all_routers = new ArrayList<SNMPHost>();


    public Snmp init(String name, String pass, int security) throws IOException {


        TransportMapping transport = new DefaultUdpTransportMapping();

        Snmp snmp = new Snmp(transport);

        transport.listen();

        OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
        SecurityModels.getInstance().addSecurityModel(usm);

        OctetString securityName = new OctetString(name);

        if (security == 1) {
            OID authProtocol = AuthMD5.ID;
            OctetString authPassphrase = new OctetString(pass);
            snmp.getUSM().addUser(securityName, new UsmUser(securityName, authProtocol, authPassphrase, null, null));
            SecurityModels.getInstance().addSecurityModel(new TSM(localEngineId, false));

        }


        if (security == 2) {
            OID authProtocol = AuthSHA.ID;
            OctetString authPassphrase = new OctetString(pass);
            snmp.getUSM().addUser(securityName, new UsmUser(securityName, authProtocol, authPassphrase, null, null));
            SecurityModels.getInstance().addSecurityModel(new TSM(localEngineId, false));

        }
        return snmp;
    }
    public UserTarget init_target(String name , String ip,String port,int hash){
        UserTarget target = new UserTarget();
        Address targetAddress = GenericAddress.parse("udp:" + ip + "/" + port);
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(3000);
        target.setVersion(SnmpConstants.version3);
        if(hash ==1)
        target.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);
        else if(hash ==2)
        target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
        else  target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString(name));

        return target;
    }
    public  void getRequestPdu(Snmp snmp,UserTarget target) throws IOException {

     // GetRequest pdu
        OID oid = new OID("1.3.6.1.2.1.1.7.0");  // sysServices
        PDU pdu = new ScopedPDU();

        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.7.0")));
        pdu.setType(PDU.GET);
        ResponseEvent event = snmp.send(pdu, target );

        if (pdu.getErrorStatus() == PDU.noError) {
            System.out.println("SNMPv3 GET Successful!");
            System.out.println("Received response from: "+ event.getPeerAddress());
            System. out.println (event.getResponse());//.getVariableBindings() );
            // out.println (event.getSource());

            resualt.l1="SNMPv3 GET Successful!";
            resualt.l2="Received response from: "+ event.getPeerAddress();
            resualt.l3=String.valueOf(event.getResponse());
        } else {
            System.out.println("SNMPv3 GET Unsuccessful.");
            resualt.l1="SNMPv3 GET Unsuccessful";
        }



    }
    public String chooseSubTree(int number) {
        switch (number) {
            case 1:
                return  "1.3.6.1.2.1.1.5.0";
            case 2:
                return "1.3.6.1.2.1.1.3.0";
            case 3:
                return "1.3.6.1.2.1.1.1.0";
            default:
                return "0";
        }
    }
    private  void sendSnmpV3Trap(String ip,String port) {
        try {
            Address targetAddress = GenericAddress.parse("udp:" + ip + "/"
                    + "162");
            TransportMapping transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);

            OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
            USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
            SecurityModels.getInstance().addSecurityModel(usm);
            SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES192());
            SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES256());
            SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());
            SecurityModels.getInstance().addSecurityModel(usm);

            //transport.listen();

            String username = "admin";
            String authpassphrase = "12345678";
            String privacypassphrase = "SecurityLevel.AUTH_NOPRIV";

            snmp.getUSM().addUser(    //SET THE USERNAME, PROTOCOLS, PASSPHRASES
                    new OctetString(username),
                    new UsmUser(new OctetString(username), AuthMD5.ID, new OctetString(
                            authpassphrase), null, new OctetString(privacypassphrase)));


            // Create Target
            UserTarget target = new UserTarget();
            target.setAddress(targetAddress);
            target.setRetries(1);
            target.setTimeout(11500);
            target.setVersion(SnmpConstants.version3);
            target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
            target.setSecurityName(new OctetString(username));

            // Create PDU for V3
            ScopedPDU pdu = new ScopedPDU();

            pdu.setType(ScopedPDU.NOTIFICATION);
            pdu.setRequestID(new Integer32(1234));
            pdu.add(new VariableBinding(SnmpConstants.sysUpTime));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID,
                    SnmpConstants.linkDown));
            pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.2.2.1.16"), new OctetString("Major")));

            // Send the PDU
            snmp.send(pdu, target);
            System.out.println("Sending Trap to (IP:Port)=> " + ip + ":"
                    + port);
            snmp.addCommandResponder(System.out::println);
            //  System.out.println(snmp.get(pdu, target));
            resualt.l3= snmp.get(pdu, target).toString();
            snmp.close();
        } catch (Exception e) {
            System.err.println("Error in Sending Trap to (IP:Port)=> " + ip
                    + ":" + port);
            System.err.println("Exception Message = " + e.getMessage());



        }

    }
    public  void setService(Snmp snmp,UserTarget target,String new_name,String myoid) throws IOException {

        OID oid = new OID(".1.3.6.1.2.1.1.5.0");
        PDU pdu = new ScopedPDU();
        pdu.add(new VariableBinding(oid ,new OctetString(new_name)));
        pdu.setType(PDU.SET);

        ResponseEvent response = snmp.send(pdu,target);

        PDU responsePDU = response.getResponse();

        if (response.getResponse() == null)
            System.out.println("Time out..");
        else
            System.out.println( response.getResponse().getErrorStatusText());
            resualt.l3=response.getResponse().getErrorStatusText();
    }
    public  void getService(Snmp snmp,UserTarget target,String myoid) throws IOException {

        OID oid = new OID(myoid);
        PDU pdu = new ScopedPDU();
        pdu.add(new VariableBinding(new OID(myoid)));
        pdu.setType(PDU.GET);

        ResponseEvent response = snmp.send(pdu, target);

        PDU responsePDU = response.getResponse();
        if (response.getResponse() == null)
            System.out.println("Time out..");

        else
        {      response.getResponse().get(0).toString().split("=");
            String result[] = response.getResponse().get(0).toString().split("=");
            System.out.println(result[1]);
            resualt.l6=result[1];
        }
    }
    public  void getBulkService(Snmp snmp,UserTarget target)throws IOException{


        PDU pdu = new ScopedPDU();
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.5.0")));
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.3.0")));
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.1.1.0")));
        pdu.setType(PDU.GETBULK);

        ResponseEvent response = snmp.send(pdu, target);
        PDU responsePDU = response.getResponse();




        if (response.getResponse() == null)
            System.out.println("Time out..");

        else
        {
            for (Object vb : response.getResponse().getVariableBindings())
            {
                System.out.println(vb.toString());}
            System.out.println( response.getResponse().getErrorStatusText());
            resualt.l3=response.getResponse().toString();
            resualt.l4=response.getResponse().getErrorStatusText();
        }

    }
    private void snmpWalk(Snmp snmp,UserTarget target) throws IOException {
        JFrame f = new JFrame();
        JTextArea textArea_res1 =new JTextArea();
        f.setSize(470, 400);
        f.add(textArea_res1);
        JScrollPane scrollPane = new JScrollPane(textArea_res1);
        scrollPane.setBounds(40, 40, 200, 100);
        f.add(scrollPane);
        f.setVisible(true);
        f.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        OID oid;
        try {
            oid = new OID(".1.3.6.1.2.1.2.2.1.2");// .1.3.6.1.2.1.2.2
        } catch (Exception e) {
            System.err.println("Failed.");
            throw e;
        }


        TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory());
        List<TreeEvent> events = treeUtils.getSubtree(target, oid);
        if(events == null || events.isEmpty()) {
            System.out.println("Failed");
            System.exit(1);
        }


        for (TreeEvent event : events) {
            if(event == null) {
                continue;
            }
            if (event.isError()) {
                System.err.println("oid [" + oid + "] " + event.getErrorMessage());
                continue;
            }

            VariableBinding[] varBindings = event.getVariableBindings();
            if(varBindings == null || varBindings.length == 0) {
                continue;
            }
            for (VariableBinding varBinding : varBindings) {
                int  i=1;
                if (varBinding == null) {
                    continue;
                }
                resualt.l7= varBinding.getOid().toString();
                resualt.l8=varBinding.getVariable().getSyntaxString();
                  resualt.l9=varBinding.getVariable().toString();
                        System.out.println(

                        varBinding.getOid() +
                                " : " +
                                varBinding.getVariable().getSyntaxString() +
                                " : " +
                                varBinding.getVariable());
                textArea_res1.append("|  "+resualt.l7+"          |          "+ resualt.l8 + "          |          "+resualt.l9 +"\r\n" +"|--------------------------------------------------------------------------------------------------------------|"+"\r\n");

            }
        }
        OID oid1;
        try {
            oid = new OID(".1.3.6.1.2.1.4.20.1.1");
        } catch (Exception e) {
            System.err.println("Failed.");
            throw e;
        }


        TreeUtils treeUtils1 = new TreeUtils(snmp, new DefaultPDUFactory());
        List<TreeEvent> events1 = treeUtils1.getSubtree(target, oid);
        if(events1 == null || events1.isEmpty()) {
            System.out.println("Failed");
            System.exit(1);
        }


        for (TreeEvent event : events1) {
            if(event == null) {
                continue;
            }
            if (event.isError()) {
                System.err.println("oid [" + oid + "] " + event.getErrorMessage());
                continue;
            }

            VariableBinding[] varBindings1 = event.getVariableBindings();
            if(varBindings1 == null || varBindings1.length == 0) {
                continue;
            }
            for (VariableBinding varBinding : varBindings1) {

                if (varBinding == null) {
                    continue;
                }
                //resualt.l7= varBinding.getOid().toString();
                resualt.l10=varBinding.getVariable().getSyntaxString();
                resualt.l11=varBinding.getVariable().toString();
                System.out.println(

                        varBinding.getOid() +
                                " : " +
                                varBinding.getVariable().getSyntaxString() +
                                " : " +
                                varBinding.getVariable());

                textArea_res1.append("|  "+resualt.l10+"          |          "+ resualt.l11 + "          |          " +"\r\n" +"|--------------------------------------------------------------------------------------------------------------|"+"\r\n");

            }
        }

        for (TreeEvent event : events1) {
            if(event == null) {
                continue;
            }
            if (event.isError()) {
                System.err.println("oid [" + oid + "] " + event.getErrorMessage());
                continue;
            }

            VariableBinding[] varBindings1 = event.getVariableBindings();
            if(varBindings1 == null || varBindings1.length == 0) {
                continue;
            }
            for (VariableBinding varBinding : varBindings1) {

                if (varBinding == null) {
                    continue;
                }
                //resualt.l7= varBinding.getOid().toString();
                resualt.l10=varBinding.getVariable().getSyntaxString();
                resualt.l11=varBinding.getVariable().toString();
                System.out.println(

                        varBinding.getOid() +
                                " : " +
                                varBinding.getVariable().getSyntaxString() +
                                " : " +
                                varBinding.getVariable());

                textArea_res1.append("|  "+resualt.l10+"          |          "+ resualt.l11 + "          |          " +"\r\n" +"|--------------------------------------------------------------------------------------------------------------|"+"\r\n");

            }
        }

        OID oid2;
        try {
            oid = new OID(".1.3.6.1.2.1.4.20.1.3");
        } catch (Exception e) {
            System.err.println("Failed.");
            throw e;
        }


        TreeUtils treeUtils2 = new TreeUtils(snmp, new DefaultPDUFactory());
        List<TreeEvent> events2 = treeUtils2.getSubtree(target, oid);
        if(events2 == null || events2.isEmpty()) {
            System.out.println("Failed");
            System.exit(1);
        }


        for (TreeEvent event : events2) {
            if(event == null) {
                continue;
            }
            if (event.isError()) {
                System.err.println("oid [" + oid + "] " + event.getErrorMessage());
                continue;
            }

            VariableBinding[] varBindings2 = event.getVariableBindings();
            if(varBindings2 == null || varBindings2.length == 0) {
                continue;
            }
            for (VariableBinding varBinding : varBindings2) {

                if (varBinding == null) {
                    continue;
                }
                //resualt.l7= varBinding.getOid().toString();
                //resualt.l12=varBinding.getVariable().getSyntaxString();
                resualt.l13=varBinding.getVariable().toString();
                System.out.println(

                        varBinding.getOid() +
                                " : " +
                                varBinding.getVariable().getSyntaxString() +
                                " : " +
                                varBinding.getVariable());

                textArea_res1.append("|  "+resualt.l13+"          |          "+"\r\n" );
                        //+ resualt.l11 + "          |          " +"\r\n" +"|--------------------------------------------------------------------------------------------------------------|"+"\r\n");

            }
        }

        snmp.close();
    }
    private void snmpWalk2(Snmp snmp,UserTarget target) throws IOException {
        JFrame f = new JFrame();                            // أي قمنا بإنشاء نافذة JFrame هنا أنشأنا كائن من الكلاس
        JTextArea textArea_res1 =new JTextArea();

        f.setSize(480, 600);                                // هنا قمنا بتحديد حجم النافذة. عرضها 500 و طولها 400
        f.add(textArea_res1);

        // عند الحاجة Scroll Bar حتى تظهر JScrollPane هنا وضعنا الصورة بداخل كائن من الكلاس
        JScrollPane scrollPane = new JScrollPane(textArea_res1);

        // كعنصر النافذة الوحيد scrollPane هنا وضعنا الـ
        scrollPane.setBounds(40, 40, 200, 100);
        f.add(scrollPane);

        f.setVisible(true);                                 // هنا جعلنا النافذة مرئية

        f.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        OID oid;
        try {
            oid = new OID(".1.3.6.1.2.1.2.2");//
        } catch (Exception e) {
            System.err.println("Failed.");
            throw e;
        }


        TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory());
        List<TreeEvent> events = treeUtils.getSubtree(target, oid);
        if(events == null || events.isEmpty()) {
            System.out.println("Failed");
            System.exit(1);
        }


        for (TreeEvent event : events) {
            if(event == null) {
                continue;
            }
            if (event.isError()) {
                System.err.println("oid [" + oid + "] " + event.getErrorMessage());
                continue;
            }

            VariableBinding[] varBindings = event.getVariableBindings();
            if(varBindings == null || varBindings.length == 0) {
                continue;
            }
            for (VariableBinding varBinding : varBindings) {
                int  i=1;
                if (varBinding == null) {
                    continue;
                }
                resualt.l7= varBinding.getOid().toString();
                resualt.l8=varBinding.getVariable().getSyntaxString();
                resualt.l9=varBinding.getVariable().toString();
                System.out.println(

                        varBinding.getOid() +
                                " : " +
                                varBinding.getVariable().getSyntaxString() +
                                " : " +
                                varBinding.getVariable());
                textArea_res1.append("|  "+resualt.l7+"          |          "+ resualt.l8 + "          |          "+resualt.l9 +"\r\n" +"|--------------------------------------------------------------------------------------------------------------|"+"\r\n");

            }
        }

        snmp.close();
    }

    static    ImageIcon icon = new ImageIcon("3d.jpg");




    public static void  main(String[] args) throws IOException {
        Snmpproject snmpp = new  Snmpproject();
        JFrame frame = new JFrame("SNMP");
        frame.getContentPane().add(new JPanelWithBackground("3d.jpg"));
        Container container = frame.getContentPane();
        GroupLayout groupLayout = new GroupLayout(container);
        container.setLayout(groupLayout);
        groupLayout.setAutoCreateGaps(true);
        groupLayout.setAutoCreateContainerGaps(true);
        groupLayout.preferredLayoutSize(container);



        JLabel label_1 = new JLabel("Name");JLabel label_2 = new JLabel("Password");JLabel label_3 = new JLabel("ip");JLabel label_4 = new JLabel("port");JLabel label_5 = new JLabel("hash fun 1 md5 or 2 sha");JLabel label_6 = new JLabel("Set New Name:");JLabel label_7 = new JLabel("Active trap");JLabel label_8 = new JLabel("Get IFtable");JLabel label_9 = new JLabel("SecurityLevel");
        JTextField textField_1 = new JTextField();
        JTextField textField_2 = new JTextField();JTextField textField_3 = new JTextField();JTextField textField_4 = new JTextField();JTextField textField_5 = new JTextField();JTextField textField_6 = new JTextField();
        JButton button_1 = new JButton("GET");JButton button_2 = new JButton("sysName");JButton button_3 = new JButton("sysUpTime");JButton button_4 = new JButton("SysDescr");JButton button_5 = new JButton("GetBulk");JButton button_6 = new JButton("Set");JButton trapbutton = new JButton("Active");JButton button_8 = new JButton("Get Now");
        String[] items = { "md5", "sha" };
        JComboBox comboBox = new JComboBox( items );
        String[] items1 = { "NoAuthNoPriv", "AuthNoPriv","AuthPriv" };
        JComboBox comboBox1= new JComboBox( items1 );
        groupLayout.setHorizontalGroup(
                groupLayout.createSequentialGroup()
                        .addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(label_1).addComponent(label_2).addComponent(label_3).addComponent(label_4).addComponent(label_5).addComponent(label_9))
                        .addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(textField_1).addComponent(textField_2).addComponent(textField_3).addComponent(textField_4).addComponent(comboBox).addComponent(comboBox1)
                                .addGroup(groupLayout.createSequentialGroup().addComponent(button_1).addComponent(button_2).addComponent(button_3).addComponent(button_4).addComponent(button_5)))
        );
        groupLayout.setVerticalGroup(
                groupLayout.createSequentialGroup()
                        .addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(label_1).addComponent(textField_1))
                        .addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(label_2).addComponent(textField_2))
                        .addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(label_3).addComponent(textField_3))
                        .addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(label_4).addComponent(textField_4))
                        .addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(label_5).addComponent(comboBox))
                        .addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(label_9).addComponent(comboBox1)).addGroup(groupLayout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(button_1).addComponent(button_2).addComponent(button_3).addComponent(button_4).addComponent(button_5))
        );

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
          frame.pack();
        frame.setSize(1324, 860);
     //   Font newFont = new Font("Arial", Font.BOLD, 20);
        frame.setVisible(true);
        Thread t = new Thread((Runnable) new Snmpproject());
        t.start();
       // JTextField textField_res = new JTextField();
        JTextArea textArea_res = new JTextArea();
        JTextArea trapArea = new JTextArea();
        frame.add(textArea_res);
        frame.add(comboBox);
        frame.add(comboBox1);
        frame.add(label_6);frame.add(button_6);frame.add(textField_6);frame.add(label_7);frame.add(trapbutton); frame.add(label_8);frame.add(button_8);
        textArea_res.setBounds(160, 240, 500, 100);
        label_6.setBounds(10, 360, 100, 30);
        button_6.setBounds(160, 360, 70, 30);
        textField_6.setBounds(250, 360, 100, 30);
        label_7.setBounds(10, 400, 50, 30);
        trapbutton.setBounds(160, 400, 70, 30);
        JScrollPane scroll = new JScrollPane(trapArea, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scroll.setBounds(250, 400, 300, 160);
        frame.add(scroll);
//        frame.add(trapArea);
        label_8.setBounds(10, 600, 100, 30);
        button_8.setBounds(160, 600, 100, 30);

        JComboBox all_snmps = new JComboBox();
        all_snmps.setBounds(1000, 25,200,20);
        JButton save_snmp = new JButton("Save");
        save_snmp.setBounds(1100, 80, 70, 50);
        frame.add(save_snmp);
        frame.add(all_snmps);
        all_snmps.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent event) {
                if (event.getStateChange() == ItemEvent.SELECTED) {
                    int item = Integer.parseInt((String) event.getItem());
                    SNMPHost tmp = all_routers.get(item);
                    textField_1.setText(tmp.username);
                    textField_2.setText(tmp.password);
                    textField_3.setText(tmp.ip);
                    textField_4.setText(tmp.port);
                }
            }
        });
        save_snmp.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                SNMPHost tmp = new SNMPHost();
                tmp.username = textField_1.getText();
                tmp.password = textField_2.getText();
                tmp.ip = textField_3.getText();
                tmp.port = textField_4.getText();
                all_routers.add(tmp);
                all_snmps.addItem(all_routers.indexOf(tmp) + "");
            }
        });



        button_1.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                    name = textField_1.getText();
                    pass = textField_2.getText();
                    ip = textField_3.getText();
                    port= textField_4.getText();
                    if(comboBox.getSelectedItem()=="md5") security=1;
                    else if(comboBox.getSelectedItem()=="sha") security=2;
                    if(comboBox1.getSelectedItem()=="NoAuthNoPriv")  hash=1;
                    else if(comboBox1.getSelectedItem()=="AuthNoPriv") hash=2;
                    else if(comboBox1.getSelectedItem()=="AuthPriv") hash=3;
                System.out.println(name);
                    System.out.println(pass);
                    System.out.println(ip);
                    System.out.println(port);
                    System.out.println(security);
                System.out.println(hash);
                pause=true;
                System.out.println("zzzzzzzzz");
                if(pause) {
                    Snmp snmp = null;
                    try {
                        snmp = snmpp.init(snmpp.name, snmpp.pass, snmpp.security);
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                    UserTarget target = snmpp.init_target(snmpp.name, snmpp.ip, snmpp.port,snmpp.hash);
                    try {
                        snmpp.getRequestPdu(snmp, target);
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
                textArea_res.setText(resualt.l1+"\r\n"+ resualt.l2 + "\r\n"+resualt.l3+ "\r\n" );
 }
        });
        button_2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                Snmp   snmp = null;
                try {
                    if(comboBox.getSelectedItem()=="md5") security=1;
                    else if(comboBox.getSelectedItem()=="sha") security=2;
                    if(comboBox1.getSelectedItem()=="NoAuthNoPriv")  hash=1;
                    else if(comboBox1.getSelectedItem()=="AuthNoPriv") hash=2;
                    else if(comboBox1.getSelectedItem()=="AuthPriv") hash=3;
                    System.out.println("zxzfzfsdfsdfs");
                    snmp = snmpp.init(snmpp.name, snmpp.pass, snmpp.security);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                UserTarget target = snmpp.init_target(snmpp.name, snmpp.ip, snmpp.port,snmpp.hash);
                try {
                    snmpp.getService(snmp, target,"1.3.6.1.2.1.1.5.0");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
          //

                textArea_res.setText(resualt.l6+ "\r\n" );
            }
        });
        button_3.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                Snmp   snmp = null;
                try {
                    snmp = snmpp.init(snmpp.name, snmpp.pass, snmpp.security);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                UserTarget target = snmpp.init_target(snmpp.name, snmpp.ip, snmpp.port,snmpp.hash);
                try {
                    snmpp.getService(snmp, target,"1.3.6.1.2.1.1.3.0");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }


                textArea_res.setText(resualt.l6+ "\r\n" );
            }
        });

        button_4.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                Snmp   snmp = null;
                try {
                    snmp = snmpp.init(snmpp.name, snmpp.pass, snmpp.security);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                UserTarget target = snmpp.init_target(snmpp.name, snmpp.ip, snmpp.port,snmpp.hash);
                try {
                    snmpp.getService(snmp, target,"1.3.6.1.2.1.1.1.0");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }


                textArea_res.setText(resualt.l6+ "\r\n" );
            }
        });

        button_5.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                Snmp   snmp = null;
                try {
                    snmp = snmpp.init(snmpp.name, snmpp.pass, snmpp.security);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                UserTarget target = snmpp.init_target(snmpp.name, snmpp.ip, snmpp.port,snmpp.hash);
                try {
                    snmpp.getBulkService(snmp, target);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }


                textArea_res.setText(resualt.l3+ "\r\n"+resualt.l4 );
            }
        });

        button_6.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                Snmp   snmp = null;
                try {
                    snmp = snmpp.init(snmpp.name, snmpp.pass, snmpp.security);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                UserTarget target = snmpp.init_target(snmpp.name, snmpp.ip, snmpp.port,snmpp.hash);
                try {
                    snmpp.setService(snmp, target,textField_6.getText(),"1");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }


                textArea_res.setText(resualt.l3+ "\r\n" );
            }
        });
        trapbutton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {


//                    snmpp.sendSnmpV3Trap(snmpp.ip,snmpp.port);
//                    textArea_res.setText(resualt.l3 + "\r\n");
                Thread trap = new Thread(new TrapReceiver(trapArea));
                trap.start();


            }
        });
        button_8.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                Snmp   snmp = null;
                try {
                    snmp = snmpp.init(snmpp.name, snmpp.pass, snmpp.security);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                UserTarget target = snmpp.init_target(snmpp.name, snmpp.ip, snmpp.port,snmpp.hash);
                try {
                  //  snmpp.snmpWalk(snmp, target);
                   snmpp.snmpWalk2(snmp, target);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }



            }
        });



    }


    @Override
    public void run() {

    }
}