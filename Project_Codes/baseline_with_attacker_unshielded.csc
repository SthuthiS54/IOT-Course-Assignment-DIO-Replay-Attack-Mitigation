<?xml version="1.0" encoding="UTF-8"?>
<simconf version="2023090101">
  <simulation>
    <title>RPL DIO Replay Attack Mitigation Evaluation</title>
    <randomseed>123456</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.UDGM
      <transmitting_range>50.0</transmitting_range>
      <interference_range>100.0</interference_range>
      <success_ratio_tx>1.0</success_ratio_tx>
      <success_ratio_rx>1.0</success_ratio_rx>
    </radiomedium>
    <events>
      <logoutput>40000</logoutput>
    </events>
    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <description>RPL Root (DODAG Root)</description>
      <source>[CONFIG_DIR]/../rpl-udp/udp-server.c</source>
      <commands>make clean TARGET=cooja
make udp-server.cooja TARGET=cooja</commands>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Battery</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiVib</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRS232</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiBeeper</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRadio</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiButton</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiPIR</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiClock</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiLED</moteinterface>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="0.0" y="0.0" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>1</id>
        </interface_config>
      </mote>
    </motetype>
    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <description>RPL Node (Protected)</description>
      <source>[CONFIG_DIR]/baseline/rpl-dio-baseline.c</source>
      <commands>make clean TARGET=cooja

make rpl-dio-baseline.cooja TARGET=cooja</commands>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Battery</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiVib</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRS232</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiBeeper</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRadio</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiButton</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiPIR</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiClock</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiLED</moteinterface>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="25.0" y="0.0" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>2</id>
        </interface_config>
      </mote>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="50.0" y="0.0" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>3</id>
        </interface_config>
      </mote>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="12.5" y="21.65" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>4</id>
        </interface_config>
      </mote>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="37.5" y="21.65" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>5</id>
        </interface_config>
      </mote>
    </motetype>
    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <description>Network Evaluator Node</description>
      <source>[CONFIG_DIR]/evaluator/rpl-dio-evaluator.c</source>
      <commands>make clean TARGET=cooja
make rpl-dio-evaluator.cooja TARGET=cooja</commands>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Battery</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiVib</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRS232</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiBeeper</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRadio</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiButton</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiPIR</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiClock</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiLED</moteinterface>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="25.0" y="-15.0" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>10</id>
        </interface_config>
      </mote>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="-10.0" y="21.65" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>11</id>
        </interface_config>
      </mote>
    </motetype>
    <motetype>
      org.contikios.cooja.contikimote.ContikiMoteType
      <description>DIO Replay Attacker</description>
      <source>[CONFIG_DIR]/attacker/rpl-dio-attacker.c</source>
      <commands>make clean TARGET=cooja
make rpl-dio-attacker.cooja TARGET=cooja</commands>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Battery</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiVib</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRS232</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiBeeper</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiRadio</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiButton</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiPIR</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiClock</moteinterface>
      <moteinterface>org.contikios.cooja.contikimote.interfaces.ContikiLED</moteinterface>
      <mote>
        <interface_config>
          org.contikios.cooja.interfaces.Position
          <pos x="25.0" y="43.3" />
        </interface_config>
        <interface_config>
          org.contikios.cooja.contikimote.interfaces.ContikiMoteID
          <id>99</id>
        </interface_config>
      </mote>
    </motetype>
  </simulation>
  <plugin>
    org.contikios.cooja.plugins.Visualizer
    <plugin_config>
      <moterelations>true</moterelations>
      <skin>org.contikios.cooja.plugins.skins.IDVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.GridVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.TrafficVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.AddressVisualizerSkin</skin>
      <viewport>2.5 0.0 0.0 2.5 100.0 120.0</viewport>
    </plugin_config>
    <bounds x="280" y="0" height="400" width="400" z="4" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.LogListener
    <plugin_config>
      <filter>DIO|Evaluator|Mitigation</filter>
      <formatted_time />
      <coloring />
    </plugin_config>
    <bounds x="0" y="400" height="300" width="800" z="1" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.LogListener
    <plugin_config>
      <filter>CSV|EVALUATION|Stability</filter>
      <formatted_time />
      <coloring />
    </plugin_config>
    <bounds x="0" y="0" height="942" width="2130" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.TimeLine
    <plugin_config>
      <mote>0</mote>
      <mote>1</mote>
      <mote>2</mote>
      <mote>3</mote>
      <mote>4</mote>
      <mote>5</mote>
      <mote>6</mote>
      <mote>7</mote>
      <showRadioRXTX />
      <showRadioHW />
      <showLEDs />
      <zoomfactor>500.0</zoomfactor>
    </plugin_config>
    <bounds x="0" y="700" height="200" width="800" z="5" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.MoteInterfaceViewer
    <mote_arg>0</mote_arg>
    <plugin_config>
      <interface>Position</interface>
      <scrollpos>0,0</scrollpos>
    </plugin_config>
    <bounds x="680" y="400" height="300" width="350" z="6" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.RadioLogger
    <plugin_config>
      <split>150</split>
      <formatted_time />
      <analyzers name="6lowpan-pcap" />
    </plugin_config>
    <bounds x="1030" y="400" height="300" width="500" z="3" />
  </plugin>
  <plugin>
    org.contikios.cooja.plugins.ScriptRunner
    <plugin_config>
      <script>/* Evaluation Script */
TIMEOUT(3600000); /* 1 hour simulation */

/* Track statistics */
var stats = {
  start_time: sim.getSimulationTime(),
  dio_count: 0,
  attack_detected: 0,
  blacklist_events: 0,
  evaluator_reports: 0,
  last_summary: 0
};

/* Log important events */
log.log("=== Simulation Started ===\n");
log.log("Monitoring for 1 hour...\n");

while(true) {
  YIELD();
  
  /* Check if msg is defined and convert to string */
  if(typeof msg !== 'undefined' &amp;&amp; msg != null) {
    var msgText = String(msg).toLowerCase();
    
    /* Count DIO messages */
    if(msgText.indexOf("dio") !== -1) {
      stats.dio_count++;
    }
    
    /* Detect attacks */
    if(msgText.indexOf("replay") !== -1 || msgText.indexOf("attack") !== -1) {
      stats.attack_detected++;
    }
    
    /* Track blacklist events */
    if(msgText.indexOf("blacklist") !== -1) {
      stats.blacklist_events++;
    }
    
    /* Count evaluator reports */
    if(msgText.indexOf("evaluation report") !== -1 || msgText.indexOf("[csv]") !== -1) {
      stats.evaluator_reports++;
    }
  }
  
  /* Log summary every 10 minutes (600 seconds = 600000000 microseconds) */
  var elapsed = sim.getSimulationTime() - stats.start_time;
  var seconds = elapsed / 1000000;
  
  if(seconds - stats.last_summary &gt;= 600 &amp;&amp; seconds &gt; 0) {
    stats.last_summary = seconds;
    log.log("\n╔════════════════════════════════════════╗\n");
    log.log("║     10 MINUTE SIMULATION SUMMARY       ║\n");
    log.log("╚════════════════════════════════════════╝\n");
    log.log("Time elapsed: " + Math.floor(seconds) + " seconds\n");
    log.log("DIOs observed: " + stats.dio_count + "\n");
    log.log("Attacks detected: " + stats.attack_detected + "\n");
    log.log("Blacklist events: " + stats.blacklist_events + "\n");
    log.log("Evaluator reports: " + stats.evaluator_reports + "\n");
    log.log("════════════════════════════════════════\n\n");
  }
}

/* Final summary */
log.log("\n╔════════════════════════════════════════╗\n");
log.log("║       FINAL SIMULATION SUMMARY         ║\n");
log.log("╚════════════════════════════════════════╝\n");
log.log("Total runtime: " + Math.floor(seconds) + " seconds\n");
log.log("Total DIOs: " + stats.dio_count + "\n");
log.log("Attacks detected: " + stats.attack_detected + "\n");
log.log("Blacklist events: " + stats.blacklist_events + "\n");
log.log("Evaluator reports: " + stats.evaluator_reports + "\n");
log.log("════════════════════════════════════════\n");
log.testOK();</script>
      <active>true</active>
    </plugin_config>
    <bounds x="1530" y="0" height="700" width="600" z="2" />
  </plugin>
</simconf>
