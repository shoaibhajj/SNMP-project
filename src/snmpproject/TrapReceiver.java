/**
 * Copyright 2010 TechDive.in
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.  
 *  
 */
/**
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package snmpproject;

import org.snmp4j.*;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.StateReference;
import org.snmp4j.mp.StatusInformation;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.TransportIpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.tools.console.SnmpRequest;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import javax.swing.*;
import java.io.IOException;

public class TrapReceiver implements CommandResponder, Runnable
{
  JTextArea output;
  public TrapReceiver(JTextArea output)
  {
    this.output = output;
  }

  @Override
  public void run() {
    try
    {
      this.listen(new UdpAddress("0.0.0.0/162"));
    }
    catch (IOException e)
    {
      this.output.setText(this.output.getText() + "\nError in Listening for Trap");
      this.output.setText(this.output.getText() + "\nException Message = " + e.getMessage());
    }
  }

  /**
   * This method will listen for traps and response pdu's from SNMP agent.
   */
  public synchronized void listen(TransportIpAddress address) throws IOException
  {
    AbstractTransportMapping transport;
    if (address instanceof TcpAddress)
    {
      transport = new DefaultTcpTransportMapping((TcpAddress) address);
    }
    else
    {
      transport = new DefaultUdpTransportMapping((UdpAddress) address);
    }

    ThreadPool threadPool = ThreadPool.create("DispatcherPool", 10);
    MessageDispatcher mtDispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

    // add message processing models
    mtDispatcher.addMessageProcessingModel(new MPv1());
    mtDispatcher.addMessageProcessingModel(new MPv2c());

    // add all security protocols
    SecurityProtocols.getInstance().addDefaultProtocols();
    SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

    //Create Target
    CommunityTarget target = new CommunityTarget();
    target.setCommunity( new OctetString("public"));
   
    Snmp snmp = new Snmp(mtDispatcher, transport);
    snmp.addCommandResponder(this);
   
    transport.listen();
    this.output.setText(this.output.getText() + "\nListening on " + address);

    try
    {
      this.wait();
    }
    catch (InterruptedException ex)
    {
      Thread.currentThread().interrupt();
    }
  }

  /**
   * This method will be called whenever a pdu is received on the given port specified in the listen() method
   */
  public synchronized void processPdu(CommandResponderEvent cmdRespEvent)
  {
    this.output.setText(this.output.getText() + "\nReceived PDU...");
    PDU pdu = cmdRespEvent.getPDU();
    if (pdu != null)
    {

      this.output.setText(this.output.getText() + "\nTrap Type = " + pdu.getType());
      this.output.setText(this.output.getText() + "\nVariable Bindings = " + pdu.getVariableBindings());
      int pduType = pdu.getType();
      if ((pduType != PDU.TRAP) && (pduType != PDU.V1TRAP) && (pduType != PDU.REPORT)
      && (pduType != PDU.RESPONSE))
      {
        pdu.setErrorIndex(0);
        pdu.setErrorStatus(0);
        pdu.setType(PDU.RESPONSE);
        StatusInformation statusInformation = new StatusInformation();
        StateReference ref = cmdRespEvent.getStateReference();
        try
        {
          this.output.setText(this.output.getText() + "\n" + cmdRespEvent.getPDU());
          cmdRespEvent.getMessageDispatcher().returnResponsePdu(cmdRespEvent.getMessageProcessingModel(),
          cmdRespEvent.getSecurityModel(), cmdRespEvent.getSecurityName(), cmdRespEvent.getSecurityLevel(),
          pdu, cmdRespEvent.getMaxSizeResponsePDU(), ref, statusInformation);
        }
        catch (MessageException ex)
        {
          this.output.setText(this.output.getText() + "\nError while sending response: " + ex.getMessage());
          LogFactory.getLogger(SnmpRequest.class).error(ex);
        }
      }
    }
  }
}