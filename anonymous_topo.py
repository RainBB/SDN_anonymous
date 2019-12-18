from mininet.topo import Topo

class MyTopo( Topo ):
    "Topology with Server"

    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        h1 = self.addHost('h1', ip='10.0.0.1' )
        h2 = self.addHost('h2', ip='10.0.0.2' )
        h3 = self.addHost('h3', ip='10.0.0.3' )
        h4 = self.addHost('h4', ip='10.0.0.4' )
        h5 = self.addHost('h5', ip='10.0.0.5' )
        server = self.addHost('server', ip='10.0.0.10' )

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(server, s3)
        self.addLink(s1, s2)
        self.addLink(s2, s3)

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

class SimpleTopo( Topo ):
    "Simplified Topology"

    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches        
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')        
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s3)
        self.addLink(h4, s3)
        self.addLink(s1, s2)
        self.addLink(s2, s3)

topos = { 'mytopo': ( lambda: MyTopo() ), 'testtopo': ( lambda: TestTopo() ), 'simpletopo': ( lambda: SimpleTopo() ) }
