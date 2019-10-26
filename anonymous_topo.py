from mininet.topo import Topo

class MyTopo( Topo ):
    "Original Topology with Loop"

    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        left_s = self.addSwitch('s1')
        cen_s1 = self.addSwitch('s2')
        cen_s2 = self.addSwitch('s3')
        cen_s3 = self.addSwitch('s4')
        right_s = self.addSwitch('s5')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        # Add links
        self.addLink(h1, left_s)
        self.addLink(h2, left_s)
        self.addLink(h3, left_s)
        self.addLink(h4, right_s)
        self.addLink(h5, right_s)
        self.addLink(h6, right_s)
        self.addLink(left_s, cen_s1)
        self.addLink(left_s, cen_s2)
        self.addLink(left_s, cen_s3)
        self.addLink(cen_s1, right_s)
        self.addLink(cen_s2, right_s)
        self.addLink(cen_s3, right_s)

class TestTopo( Topo ):
    "Simplified Topology"

    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches        
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s3)
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        self.addLink(s1, s2)
        self.addLink(s2, s3)

topos = { 'mytopo': ( lambda: MyTopo() ), 'testtopo': ( lambda: TestTopo() ) }
