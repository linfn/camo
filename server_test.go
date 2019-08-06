package camo

// func upstreamServer(t *testing.T, addr string) func() {
// 	var closed int32
// 	lt, err := net.Listen("tcp", addr)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	go func() {
// 		conn, err := lt.Accept()
// 		if err != nil {
// 			if atomic.LoadInt32(&closed) == 0 {
// 				t.Log(err)
// 			}
// 			return
// 		}
// 		go func() {
// 			defer conn.Close()
// 			var buf [1024]byte
// 			for {
// 				n, err := conn.Read(buf[:])
// 				if err != nil {
// 					if err != io.EOF && atomic.LoadInt32(&closed) == 0 {
// 						t.Log(err)
// 					}
// 					return
// 				}
// 				_, err = conn.Write(buf[:n])
// 				if err != nil {
// 					t.Log(err)
// 					return
// 				}
// 			}
// 		}()
// 	}()
// 	ip, sport, err := net.SplitHostPort(addr)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	port, err := strconv.Atoi(sport)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	lu, err := net.ListenUDP("udp", &net.UDPAddr{
// 		IP:   net.ParseIP(ip),
// 		Port: port,
// 	})
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	go func() {
// 		var buf [1024]byte
// 		for {
// 			n, from, err := lu.ReadFrom(buf[:])
// 			if err != nil {
// 				if atomic.LoadInt32(&closed) == 0 {
// 					t.Log(err)
// 				}
// 				return
// 			}
// 			_, err = lu.WriteTo(buf[:n], from)
// 			if err != nil {
// 				t.Log(err)
// 			}
// 		}
// 	}()
// 	return func() {
// 		atomic.StoreInt32(&closed, 1)
// 		lt.Close()
// 		lu.Close()
// 	}
// }

// func createTestServer(t *testing.T, addr string) func() {
// 	l, err := net.Listen("tcp", addr)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	srv := NewServer(grpc.NewServer())
// 	go srv.Serve(l)

// 	return func() {
// 		srv.Stop()
// 	}
// }

// func TestServerTCP(t *testing.T) {
// 	target := "127.0.0.1:19919"
// 	defer upstreamServer(t, target)()

// 	svr := "127.0.0.1:19920"
// 	defer createTestServer(t, svr)()

// 	conn, err := grpc.Dial(svr, grpc.WithInsecure())
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer conn.Close()
// 	c := NewTunnelClient(conn)

// 	stream, err := c.Connect(metadata.AppendToOutgoingContext(context.Background(), metaEndpoint, target))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer stream.CloseSend()

// 	err = stream.Send(&TCPPacket{
// 		Data: []byte("HELLO\n"),
// 	})
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	pkt, err := stream.Recv()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if string(pkt.Data) != "HELLO\n" {
// 		t.Error("bad resp:", string(pkt.Data))
// 	}
// }
