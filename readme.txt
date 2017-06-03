1) Initial Steps
   -------------
   a) Copy the <source> folder to mininet vm's home directory < /home/mininet > 
   b) Execute the router.py for controller program written in python
   
2) Steps for executing the Controller in mininet
   -------------------------------------------
   a) Execute
     $ chmod +x pwospf.py
     $ ./run_controller
   
3) Steps for executing the topology in mininet
   -------------------------------------------
   a) Execute 
     $ chmod +x topology.py
     $ ./run_topology
   b) Open the topology file <full_topology.mn>
   c) Run the miniedit topology and mininet prompt will be open
   d) Execute a sample pingall and see the connectivity ( mininet> pingall )

4) Brief Software Design and Test results are present in the StaticRoutingReport.pdf
