#pragma once
/*
**  Copyright (C) 2012 Aldebaran Robotics
**  See COPYING for the license
*/

#ifndef _QITYPE_DETAILS_FUNCTIONTYPE_HXX_
#define _QITYPE_DETAILS_FUNCTIONTYPE_HXX_

#ifdef BOOST_FUSION_INVOKE_FUNCTION_OBJECT_MAX_ARITY
# undef BOOST_FUSION_INVOKE_FUNCTION_OBJECT_MAX_ARITY
#endif
#define BOOST_FUSION_INVOKE_FUNCTION_OBJECT_MAX_ARITY 10

#include <boost/fusion/include/mpl.hpp>
#include <boost/mpl/for_each.hpp>
#include <boost/mpl/transform_view.hpp>
#include <boost/mpl/find_if.hpp>
#include <boost/mpl/vector.hpp>
#include <boost/mpl/pop_front.hpp>
#include <boost/mpl/at.hpp>
#include <boost/mpl/placeholders.hpp>
#include <boost/mpl/max_element.hpp>
#include <boost/mpl/transform.hpp>
#include <boost/type_traits/remove_reference.hpp>
#include <boost/type_traits/add_pointer.hpp>
#include <boost/type_traits/remove_const.hpp>
#include <boost/type_traits/remove_pointer.hpp>
#include <boost/function_types/function_type.hpp>
#include <boost/function_types/function_arity.hpp>
#include <boost/function_types/function_pointer.hpp>
#include <boost/function_types/result_type.hpp>
#include <boost/function_types/parameter_types.hpp>
#include <boost/fusion/container/vector/convert.hpp>
#include <boost/fusion/include/as_vector.hpp>
#include <boost/fusion/include/as_list.hpp>
#include <boost/fusion/algorithm/transformation/transform.hpp>
#include <boost/fusion/include/transform.hpp>
#include <boost/fusion/functional/invocation/invoke_function_object.hpp>
#include <boost/fusion/container/generation/make_vector.hpp>
#include <boost/fusion/include/make_vector.hpp>
#include <boost/fusion/algorithm/iteration/for_each.hpp>
#include <boost/fusion/functional/adapter/unfused.hpp>
#include <boost/fusion/functional/generation/make_unfused.hpp>
#include <boost/fusion/functional/generation/make_fused.hpp>
#include <boost/bind.hpp>
#include <boost/any.hpp>

#include <qitype/genericvalue.hpp>
#include <qitype/details/bindtype.hxx>

namespace qi
{
  inline CallableType::CallableType()
  : _resultType(0)
  {
  }

  inline Type* CallableType::resultType()
  {
    return _resultType;
  }

  inline const std::vector<Type*>& CallableType::argumentsType()
  {
    return _argumentsType;
  }

  inline GenericValuePtr GenericFunction::operator()(const std::vector<GenericValuePtr>& args)
  {
    return call(args);
  }

  namespace detail
  {
    struct PtrToConstRef
    {
      // Drop the const, it prevents method calls from working
      template <typename Sig>
      struct result;

      template <class Self, typename T>
      struct result< Self(T) >
      {
        typedef typename boost::add_reference<
        //typename boost::add_const<
        typename boost::remove_pointer<
        typename boost::remove_reference<T>::type
        >::type
        //  >::type
        >::type type;
      };
      template<typename T> inline
      T& operator() (T* const &ptr) const
      {
        static Type* type = typeOf<T>();
        // Careful here, a wrong cast will create a variable on the stack, but
        // we need to pass &ptr
        void* res  = type->ptrFromStorage((void**)&ptr);
        return *(T*)res;
      }
    };
    template<typename T> struct remove_constptr
    {
      typedef T type;
    };
    template<typename T> struct remove_constptr<const T*>
    {
      typedef T* type;
    };
    struct fill_arguments
    {
      inline fill_arguments(std::vector<Type*>* target)
      : target(target) {}

      template<typename T> void operator()(T*) const
      {
        Type* result = typeOf<
          typename remove_constptr<
            typename boost::remove_const<
               typename boost::remove_reference<T>::type
            >::type>::type>();
        target->push_back(result);
      }
      std::vector<Type*>* target;
    };

    struct Transformer
    {
    public:
      inline Transformer(void** args)
      : args(args)
      , pos(0)
      {}
      template <typename Sig>
      struct result;

      template <class Self, typename T>
      struct result< Self(T) >
      {
        typedef T type;
      };
      template<typename T>
      inline void
      operator() (T* &v) const
      {
        v = (T*)args[pos++];
      }
      void** args;
      mutable unsigned int pos;
    };

    template<typename SEQ, typename F> void* apply(SEQ sequence,
      F& function, void** args, unsigned int argc)
    {
      GenericValuePtrCopy res;
      boost::fusion::for_each(sequence, Transformer(args));
      res(), boost::fusion::invoke_function_object(function,
        boost::fusion::transform(sequence,
          PtrToConstRef()));
      return res.value;
    }
    template<typename T> struct Ident
    {
    };

    struct checkForNonConstRef
    {
      template<typename T> void operator()(Ident<T>)
      {
        if (boost::is_reference<T>::value && !boost::is_const<
          typename boost::remove_reference<T>::type>::value)
          qiLogWarning("qi.meta") << "Function argument is a non-const reference: " << typeid(T).name();
      }
    };
  } // namespace detail


  template<typename T, int arity> struct SafePopFront
  {
    typedef typename boost::mpl::pop_front<T>::type type;
  };

  template<typename T> struct SafePopFront<T, 0>
  {
    typedef T type;
  };

  template<typename T> class FunctionTypeImpl:
  public FunctionType
  {
  public:
    FunctionTypeImpl(bool isMethod = false)
    {
      _resultType = typeOf<typename boost::function_types::result_type<T>::type >();

      typedef typename boost::function_types::parameter_types<T>::type ArgsType;
      // Detect and warn about non-const reference arguments
      if (isMethod) // skip first argument. Runtime switch so cant pop_front directly
        boost::mpl::for_each<
         boost::mpl::transform_view<
           typename SafePopFront<ArgsType, boost::function_types::function_arity<T>::value>::type,
           detail::Ident<boost::mpl::_1>
           > >(detail::checkForNonConstRef());
      else
      boost::mpl::for_each<
         boost::mpl::transform_view<ArgsType,
           detail::Ident<boost::mpl::_1>
           > >(detail::checkForNonConstRef());
      // Generate and store a Type* for each argument
      boost::mpl::for_each<
        boost::mpl::transform_view<ArgsType,
        boost::add_pointer<
        boost::remove_const<
        boost::remove_reference<boost::mpl::_1> > > > >(detail::fill_arguments(&_argumentsType));
    }

    virtual void* call(void* func, void** args, unsigned int argc)
    {
      boost::function<T>* f = (boost::function<T>*)ptrFromStorage(&func);
      typedef typename boost::function_types::parameter_types<T>::type ArgsType;
      typedef typename  boost::mpl::transform_view<ArgsType,
      boost::remove_const<
      boost::remove_reference<boost::mpl::_1> > >::type BareArgsType;
      typedef typename boost::mpl::transform_view<BareArgsType,
      boost::add_pointer<boost::mpl::_1> >::type PtrArgsType;
      return detail::apply(boost::fusion::as_vector(PtrArgsType()), *f, args, argc);
    }

    _QI_BOUNCE_TYPE_METHODS(DefaultTypeImplMethods<boost::function<T> >);
  };

  template<typename T> FunctionType* makeFunctionType()
  {
    static FunctionTypeImpl<T>* result = 0;
    if (!result)
      result = new FunctionTypeImpl<T>();
    return result;
  }


  namespace detail
  {
    // Use helper structures for which template partial specialisation is possible
    template<typename T> struct GenericFunctionMaker
    {
      static GenericFunction make(T func)
      {
        return GenericFunctionMaker<typename boost::function<T> >::make(boost::function<T>(func));
      }
    };
    template<typename T> struct GenericFunctionMaker<T*>
    {
      static GenericFunction make(T* func)
      {
         return GenericFunctionMaker<typename boost::function<T> >::make(boost::function<T>(func));
      }
    };
    template<typename R, typename F, typename B>
    struct GenericFunctionMaker<boost::_bi::bind_t<R, F, B> >
    {
      static GenericFunction make(boost::_bi::bind_t<R, F, B> v)
      {
        typedef typename boost::function<typename boost_bind_function_type<
        boost::_bi::bind_t<R, F, B> >::type> CompatType;
        CompatType f = v;
        return makeGenericFunction(f);
      }
    };
    template<typename T> struct GenericFunctionMaker<boost::function<T> >
    {
      static GenericFunction make(boost::function<T> func)
      {
         assert(sizeof(boost::function<T>) == sizeof(boost::function<void ()>));
         GenericFunction res;
         res.type = makeFunctionType<T>();
         res.value = res.type->clone(res.type->initializeStorage(&func));
         return res;
      }
    };
    template<typename T> struct GenericFunctionMaker<const T&>
    : public GenericFunctionMaker<T> {};
    template<> struct GenericFunctionMaker<GenericFunction>
    {
      static GenericFunction make(GenericFunction func)
      {
        return func;
      }
    };
  }

  template<typename T>
  GenericFunction makeGenericFunction(T f)
  {
    return detail::GenericFunctionMaker<T>::make(f);
  }

  inline GenericFunction::GenericFunction()
  : type(0), value(0) {}

  inline GenericFunction::GenericFunction(const GenericFunction& b)
  {
    type = b.type;
    value = type?type->clone(b.value):0;
  }

  inline GenericFunction& GenericFunction::operator=(const GenericFunction& b)
  {
    this->~GenericFunction();
    type = b.type;
    value = type?type->clone(b.value):0;
    return *this;
  }

  inline GenericFunction::~GenericFunction()
  {
    if (type)
      type->destroy(value);
  }

  inline GenericValuePtr GenericFunction::call(const std::vector<GenericValuePtr>& args)
  {
    return type->call(value, args);
  }

namespace detail
{
  /* Call a boost::function<F> binding the first argument.
  * Can't be done just with boost::bind without code generation.
  */
  template<typename F>
  struct FusedBindOne
  {
    template <class Seq>
    struct result
    {
      typedef typename boost::function_types::result_type<F>::type type;
    };

    template <class Seq>
    typename result<Seq>::type
    operator()(Seq const & s) const
    {
      return ::boost::fusion::invoke_function_object(func,
        ::boost::fusion::push_front(s, boost::ref(const_cast<ArgType&>(*arg1))));
    }
    ::boost::function<F> func;
    typedef typename boost::remove_reference<
      typename ::boost::mpl::front<
        typename ::boost::function_types::parameter_types<F>::type
        >::type>::type ArgType;
    void setArg(ArgType* val) { arg1 = val;}
    ArgType* arg1;

  };

}

template<typename C, typename F> GenericFunction makeGenericFunction(C* inst, F func)
{
  // Return type
  typedef typename ::boost::function_types::result_type<F>::type RetType;
  // All arguments including class pointer
  typedef typename ::boost::function_types::parameter_types<F>::type MemArgsType;
  // Pop class pointer
  typedef typename ::boost::mpl::pop_front< MemArgsType >::type ArgsType;
  // Synthethise exposed function type
  typedef typename ::boost::mpl::push_front<ArgsType, RetType>::type ResultMPLType;
  typedef typename ::boost::function_types::function_type<ResultMPLType>::type ResultType;
  // Synthethise non-member function equivalent type of F
  typedef typename ::boost::mpl::push_front<MemArgsType, RetType>::type MemMPLType;
  typedef typename ::boost::function_types::function_type<MemMPLType>::type LinearizedType;
  // See func as R (C*, OTHER_ARGS)
  boost::function<LinearizedType> memberFunction = func;
  boost::function<ResultType> res;
  // Create the fusor
  detail::FusedBindOne<LinearizedType> fusor;
  // Bind member function and instance
  fusor.setArg(inst);
  fusor.func = memberFunction;
  // Convert it to a boost::function
  res = boost::fusion::make_unfused(fusor);

  return makeGenericFunction(res);
}

} // namespace qi
#endif  // _QITYPE_DETAILS_FUNCTIONTYPE_HXX_
