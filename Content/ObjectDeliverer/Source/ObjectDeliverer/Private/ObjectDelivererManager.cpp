// Copyright 2019 ayumax. All Rights Reserved.
#include "ObjectDelivererManager.h"
#include "Protocol/ObjectDelivererProtocol.h"
#include "PacketRule/PacketRule.h"
#include "DeliveryBox/DeliveryBox.h"
#include "Async/Async.h"
#include "Async/UniqueLock.h"
#include "Misc/ScopeLock.h"
#include "Utils/ObjectDelivererLoggerBase.h"
#include "Utils/ODLog.h"

UObjectDelivererManager* UObjectDelivererManager::CreateObjectDelivererManager(bool _IsEventWithGameThread /* = true*/)
{
	auto manager = NewObject<UObjectDelivererManager>();
	manager->IsEventWithGameThread = _IsEventWithGameThread;
	return manager;
}

UObjectDelivererManager::UObjectDelivererManager()
	: IsEventWithGameThread(true)
	, IsDestorying(false)
{
	CurrentProtocol = nullptr;
	DeliveryBox = nullptr;
	Logger = nullptr;
}

UObjectDelivererManager::~UObjectDelivererManager()
{
}

void UObjectDelivererManager::Start(UObjectDelivererProtocol* Protocol, UPacketRule* PacketRule, UDeliveryBox* _DeliveryBox)
{
	if (!Protocol || !PacketRule)
	{
		OD_LOG(Error, TEXT("UObjectDelivererManager::Start failed: Protocol=%s, PacketRule=%s"),
			Protocol ? TEXT("valid") : TEXT("null"),
			PacketRule ? TEXT("valid") : TEXT("null"));
		return;
	}

	IsDestorying.store(false, std::memory_order_release);

	{
		UE::TUniqueLock<UE::FRecursiveMutex> lock(StateCriticalSection);
		CurrentProtocol = Protocol;
		DeliveryBox = _DeliveryBox;
		ConnectedList.Reset();
	}
	CurrentProtocolAtomic.store(Protocol, std::memory_order_release);
	DeliveryBoxAtomic.store(_DeliveryBox, std::memory_order_release);

	Protocol->SetPacketRule(PacketRule);

	TWeakObjectPtr<UObjectDelivererManager> WeakThis(this);

	if (_DeliveryBox)
	{
		_DeliveryBox->RequestSend.BindLambda([WeakThis](const UObjectDelivererProtocol* Destination, const TArray<uint8>& Buffer, const FDeliveryDataType& DataType)
		{
			auto* Manager = WeakThis.Get();
			if (!Manager || Manager->IsDestorying.load(std::memory_order_acquire))
			{
				return;
			}

			const UObjectDelivererProtocol* TargetProtocol = Destination;
			if (!TargetProtocol)
			{
				TargetProtocol = Manager->CurrentProtocolAtomic.load(std::memory_order_acquire);
			}

			Manager->SendToInternal(Buffer, TargetProtocol, DataType);
		});
	}

	Protocol->Connected.BindLambda([WeakThis](const UObjectDelivererProtocol* ConnectedObject)
	{
		if (auto* Manager = WeakThis.Get())
		{
			Manager->HandleConnected(ConnectedObject);
		}
	});

	Protocol->Disconnected.BindLambda([WeakThis](const UObjectDelivererProtocol* DisconnectedObject)
	{
		if (auto* Manager = WeakThis.Get())
		{
			Manager->HandleDisconnected(DisconnectedObject);
		}
	});

	Protocol->ReceiveData.BindLambda([WeakThis](const UObjectDelivererProtocol* FromObject, const TArray<uint8>& Buffer)
	{
		if (auto* Manager = WeakThis.Get())
		{
			Manager->HandleReceiveData(FromObject, Buffer);
		}
	});

	Protocol->Start();
}

void UObjectDelivererManager::HandleConnected(const UObjectDelivererProtocol* ConnectedObject)
{
	if (IsDestorying.load(std::memory_order_acquire)) return;

	DispatchEvent([this, ConnectedObject]()
	{
		if (IsDestorying.load(std::memory_order_acquire)) return;

		{
			UE::TUniqueLock<UE::FRecursiveMutex> lock(StateCriticalSection);
			if (IsDestorying.load(std::memory_order_relaxed)) return;
			ConnectedList.Add(ConnectedObject);
		}

		Connected.Broadcast(ConnectedObject);
	});
}

void UObjectDelivererManager::HandleDisconnected(const UObjectDelivererProtocol* DisconnectedObject)
{
	if (IsDestorying.load(std::memory_order_acquire)) return;

	DispatchEvent([this, DisconnectedObject]()
	{
		if (IsDestorying.load(std::memory_order_acquire)) return;

		{
			UE::TUniqueLock<UE::FRecursiveMutex> lock(StateCriticalSection);
			if (IsDestorying.load(std::memory_order_relaxed)) return;
			ConnectedList.Remove(DisconnectedObject);
		}

		Disconnected.Broadcast(DisconnectedObject);
	});
}

void UObjectDelivererManager::HandleReceiveData(const UObjectDelivererProtocol* FromObject, const TArray<uint8>& Buffer)
{
	if (IsDestorying.load(std::memory_order_acquire)) return;

	DispatchEvent([this, FromObject, Buffer]()
	{
		ReceiveData.Broadcast(FromObject, Buffer);

		UDeliveryBox* DeliveryBoxSnapshot = DeliveryBoxAtomic.load(std::memory_order_acquire);

		if (DeliveryBoxSnapshot)
		{
			DeliveryBoxSnapshot->NotifyReceiveBuffer(FromObject, Buffer);
		}
	});
}

void UObjectDelivererManager::DispatchEvent(TFunction<void()> EventAction)
{
	if (IsDestorying.load(std::memory_order_acquire)) return;
	if (!IsValid(this)) return;

	if (IsEventWithGameThread)
	{
		TWeakObjectPtr<UObjectDelivererManager> WeakThis(this);
		AsyncTask(ENamedThreads::GameThread, [WeakThis, EventAction = MoveTemp(EventAction)]() mutable {
			auto* Manager = WeakThis.Get();
			if (!Manager) return;
			if (Manager->IsDestorying.load(std::memory_order_acquire)) return;
			EventAction();
		});
	}
	else
	{
		if (IsDestorying.load(std::memory_order_acquire)) return;
		EventAction();
	}
}

UObjectDelivererManager* UObjectDelivererManager::WithObjectDelivererLogger(UObjectDelivererLoggerBase* InLogger)
{
	{
		UE::TUniqueLock<UE::FRecursiveMutex> lock(StateCriticalSection);
		Logger = InLogger;
	}

	if (InLogger)
	{
		ObjectDelivererLog::SetLogger(InLogger);
	}
	else
	{
		ObjectDelivererLog::ClearLogger();
	}

	return this;
}

void UObjectDelivererManager::Close()
{
	if (IsDestorying.exchange(true, std::memory_order_acq_rel))
	{
		return;
	}

	UObjectDelivererProtocol* ProtocolToClose = CurrentProtocolAtomic.exchange(nullptr, std::memory_order_acq_rel);
	UDeliveryBox* DeliveryBoxToUnbind = DeliveryBoxAtomic.exchange(nullptr, std::memory_order_acq_rel);

	// Avoid taking StateCriticalSection in Close(). If a worker thread was forcibly terminated
	// while holding the mutex in a previous code path, waiting here can deadlock teardown forever.
	// Runtime behavior now keys off the atomic snapshots above.

	if (DeliveryBoxToUnbind)
	{
		if (DeliveryBoxToUnbind->RequestSend.IsBound())
		{
			DeliveryBoxToUnbind->RequestSend.Unbind();
		}
	}

	if (!IsValid(ProtocolToClose))
	{
		return;
	}

	// Callbacks may still race during shutdown, so keep protocol delegates bound and
	// guard all callbacks with IsDestorying + weak references instead of Unbind().
	ProtocolToClose->Close();
}

void UObjectDelivererManager::Send(const TArray<uint8>& DataBuffer)
{
	const UObjectDelivererProtocol* TargetProtocol = nullptr;
	TargetProtocol = CurrentProtocolAtomic.load(std::memory_order_acquire);
	SendToInternal(DataBuffer, TargetProtocol, FDeliveryDataType::Default());
}

void UObjectDelivererManager::SendTo(const TArray<uint8>& DataBuffer, const UObjectDelivererProtocol* Target)
{
	SendToInternal(DataBuffer, Target, FDeliveryDataType::Default());
}

void UObjectDelivererManager::SendToInternal(const TArray<uint8>& DataBuffer, const UObjectDelivererProtocol* Target, const FDeliveryDataType& DataType)
{
	if (IsDestorying.load(std::memory_order_acquire)) return;
	if (!Target) return;

	UObjectDelivererProtocol* ActiveProtocol = nullptr;
	ActiveProtocol = CurrentProtocolAtomic.load(std::memory_order_acquire);

	if (!ActiveProtocol) return;

	Target->Send(DataBuffer, DataType);
}

bool UObjectDelivererManager::IsConnected()
{
	if (IsDestorying.load(std::memory_order_acquire))
	{
		return false;
	}
	if (CurrentProtocolAtomic.load(std::memory_order_acquire) == nullptr)
	{
		return false;
	}

	UE::TUniqueLock<UE::FRecursiveMutex> lock(StateCriticalSection);
	return ConnectedList.Num() > 0;
}

void UObjectDelivererManager::BeginDestroy()
{
	ObjectDelivererLog::ClearLogger();
	Close();

	Super::BeginDestroy();

}
