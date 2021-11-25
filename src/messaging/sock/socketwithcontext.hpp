#pragma once
#ifndef _QI_SOCK_SOCKETWITHCONTEXT_HPP
#define _QI_SOCK_SOCKETWITHCONTEXT_HPP
#include <ka/src.hpp>
#include <ka/mutablestore.hpp>
#include "traits.hpp"
#include "sslcontextptr.hpp"

namespace qi { namespace sock {

  // Traits to check whether a class has a get_io_service function
  // This is used to conditionally check SFINAE test
  template <typename T>
  class has_get_io_service
  {
      typedef char one;
      struct two { char x[2]; };

      template <typename C> static one test( decltype(&C::get_io_service) ) ;
      template <typename C> static two test(...);

  public:
      enum { value = sizeof(test<T>(0)) == sizeof(char) };
  };

  /// Socket bound to an ssl context.
  ///
  /// The purpose is to ensure that the ssl context has the same lifetime as
  /// the socket.
  ///
  /// Network N
  template<typename N>
  class SocketWithContext
  {
    using socket_t = SslSocket<N>;
    using io_service_t = IoService<N>;

    SslContextPtr<N> context;
    socket_t socket;

  public:
  // NetSslSocket:
    using handshake_type = HandshakeSide<socket_t>;
    using lowest_layer_type = Lowest<socket_t>;
    using next_layer_type = typename socket_t::next_layer_type;

    SocketWithContext(io_service_t& io, const SslContextPtr<N>& ctx)
      : context(ctx)
      , socket(io, *ctx)
    {
    }

    // Since Boost 1.70 get_io_service() has been removed
    // However the internal types of libqi still provide interfaces using that function
    // Thus, we conditionnally use the get_io_service() call if it exists within the socket_t implementation (e.g old boost implementations or libqi types)
    // and use the new get_executor().context() call for boost types (>=1.70)
    template <typename T = socket_t>
    typename std::enable_if<has_get_io_service<T>::value, io_service_t>::type& get_io_service()
    {
      return socket.get_io_service();
    }

    template <typename T = socket_t>
    typename std::enable_if<!has_get_io_service<T>::value, io_service_t>::type& get_io_service()
    {
      return static_cast<io_service_t&>(socket.get_executor().context());
    }


    void set_verify_mode(decltype(N::sslVerifyNone()) x)
    {
      socket.set_verify_mode(x);
    }

    template<typename H>
    void async_handshake(handshake_type x, H h)
    {
      socket.async_handshake(x, h);
    }

    lowest_layer_type& lowest_layer()
    {
      return socket.lowest_layer();
    }

    next_layer_type& next_layer()
    {
      return socket.next_layer();
    }

  // Custom:
    template<typename T, typename U>
    void async_read_some(const T& buffers, const U& handler)
    {
      socket.async_read_some(buffers, handler);
    }

    template<typename T, typename U>
    void async_write_some(const T& buffers, const U& handler)
    {
      socket.async_write_some(buffers, handler);
    }
  };
}} // namespace qi::sock

#endif // _QI_SOCK_SOCKETWITHCONTEXT_HPP
